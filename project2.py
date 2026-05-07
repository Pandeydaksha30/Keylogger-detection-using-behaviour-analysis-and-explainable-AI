import psutil
import time
import threading
import re
import json
import requests
from collections import defaultdict
from flask import Flask, jsonify, render_template_string

# --- Flask App Initialization ---
app = Flask(__name__)

# --- Configuration & State ---
# NOTE: Using a real API Key is REQUIRED for the AI triage function to work.
# Please replace "" with your actual Gemini API Key.
GEMINI_API_KEY = "AIzaSyB-M3oncoqCsB_3kkDgPZEucd_ExerSaos" 
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent"
MODEL_NAME = "gemini-2.5-flash-preview-09-2025"

suspicion_scores = defaultdict(int)
process_io_baseline = defaultdict(lambda: {'read_bytes': 0, 'write_bytes': 0})
process_net_baseline = defaultdict(int)

# Dictionaries to store state
SUSPICIOUS_PROCESSES = {}
ALL_PROCESS_CACHE = {} # Cache for all processes (used for the safe list)

# Set to track processes currently undergoing AI analysis (prevents duplicate API calls)
SUSPICIOUS_PROCESSES_AI_PENDING = set() 

# --- Heuristic Thresholds (Tunable) ---
ABNORMAL_WRITE_THRESHOLD = 1
ABNORMAL_NET_CONNS = 5
ALERT_THRESHOLD = 90 # Score that triggers AI analysis

# --- Scoring ---
SCORES = {
    'ABNORMAL_WRITE': 40,
    'SUSPICIOUS_PATH': 30,
    'OUTBOUND_NETWORK': 25,
    'ABNORMAL_NET_GROWTH': 20,
    'SUSPICIOUS_NAME': 30 
}

# --- Regex/Patterns ---
SUSPICIOUS_PATH_REGEX = re.compile(
    r'.*(temp|tmp|appdata|localappdata|downloads|public|music|videos).*',
    re.IGNORECASE
)
SUSPICIOUS_NAMES_REGEX = re.compile(
    r'(keylogger|hook|spy|svchost|system_utility|runtime|taskmgr)\.exe',
    re.IGNORECASE
)

# --- AI Integration Functions ---

def generate_ai_triage(process_data):
    """Calls the Gemini API to get a natural language threat summary."""
    if not GEMINI_API_KEY:
        print("[AI Triage] API Key not set. Returning default summary.")
        return "API Key Missing. Manual triage required."

    system_prompt = (
        "You are a Senior Threat Analyst specializing in behavioral malware detection. "
        "Analyze the provided process details (PID, name, and security reasons) and generate a concise, three-sentence summary. "
        "State the potential threat type (e.g., Keylogger, Ransomware, PUA), the severity (LOW, MEDIUM, HIGH), and the recommended user action (e.g., Terminate immediately, Review path, Monitor activity)."
    )
    user_query = f"Analyze this suspicious process data:\n{json.dumps(process_data, indent=2)}"
    
    payload = {
        "contents": [{"parts": [{"text": user_query}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
    }
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            url = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
            
            response = requests.post(
                url, 
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload),
                timeout=10 # Set a timeout for the API call
            )
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            result = response.json()
            
            # Extract text from the candidate
            text = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text')
            
            if text:
                return text.strip()
            else:
                print(f"[AI Triage Error] API response missing text content: {result}")
                return "AI analysis failed to produce text."
                
        except requests.exceptions.HTTPError as e:
            print(f"[AI Triage Error] HTTP Error on attempt {attempt + 1}: {e}")
            if e.response.status_code == 429 and attempt < max_retries - 1:
                # Handle rate limiting with exponential backoff
                wait_time = 2 ** attempt 
                print(f"[AI Triage] Rate limit hit. Waiting {wait_time}s before retry.")
                time.sleep(wait_time)
            else:
                return f"API Error: {e.response.status_code}"
                
        except requests.exceptions.RequestException as e:
            print(f"[AI Triage Error] General Request Error on attempt {attempt + 1}: {e}")
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                print(f"[AI Triage] Network error. Waiting {wait_time}s before retry.")
                time.sleep(wait_time)
            else:
                return "Network connection failed after multiple retries."
                
    return "AI analysis failed."

def ai_triage_worker(pid, name, reasons, score):
    """Thread worker function to handle the synchronous API call."""
    try:
        print(f"[AI Triage Worker] Starting analysis for PID {pid} ({name})...")
        
        # Data sent to the LLM
        process_data = {
            'pid': pid,
            'name': name,
            'score': score,
            'reasons': reasons
        }
        
        summary = generate_ai_triage(process_data)
        
        # Update the shared state
        if pid in SUSPICIOUS_PROCESSES:
            SUSPICIOUS_PROCESSES[pid]['ai_summary'] = summary
            print(f"[AI Triage Success] PID {pid} updated with summary.")
        else:
            print(f"[AI Triage Warning] PID {pid} ended before summary could be applied.")

    finally:
        # Crucial step: Remove the PID from the pending set
        if pid in SUSPICIOUS_PROCESSES_AI_PENDING:
            SUSPICIOUS_PROCESSES_AI_PENDING.remove(pid)
        print(f"[AI Triage Worker] Finished for PID {pid}.")


# --- Monitoring Core ---

def analyze_process(proc):
    pid = proc.pid
    name = proc.name()
    score = 0
    reasons = []

    try:
        exe_path = proc.exe()
        username = proc.username()

        # Update ALL_PROCESS_CACHE for the "Safe" list display
        ALL_PROCESS_CACHE[pid] = {
            'pid': pid,
            'name': name,
            'cpu_percent': proc.cpu_percent(interval=0.01), 
            'username': username,
            'score': 0
        }
        
        # --- Heuristic Checks ---
        
        # 1. Suspicious Name (30 points for svchost.exe)
        if SUSPICIOUS_NAMES_REGEX.match(name):
            reasons.append(f"Suspicious name: {name} (Base Score)")
            score += SCORES['SUSPICIOUS_NAME']
            
        # 2. Abnormal File Writes (CORE KEYLOGGER DETECTION)
        current_io = proc.io_counters()
        baseline_io = process_io_baseline[pid]
        write_diff = 0
        
        if baseline_io.get('write_bytes') is not None and baseline_io['write_bytes'] != 0:
            write_diff = current_io.write_bytes - baseline_io['write_bytes']
            
        process_io_baseline[pid]['write_bytes'] = current_io.write_bytes
        
        if write_diff > ABNORMAL_WRITE_THRESHOLD:
            # print(f"[HEURISTIC HIT] PID {pid} exceeded write threshold ({write_diff} B)!")
            reasons.append(f"Abnormal file write rate detected: {write_diff} B/cycle")
            score += SCORES['ABNORMAL_WRITE']

        # 3. Suspicious Path 
        if SUSPICIOUS_PATH_REGEX.match(exe_path):
            reasons.append(f"Suspicious path: ...{exe_path[-50:]}")
            score += SCORES['SUSPICIOUS_PATH']

        # 4. Network Connections
        connections = proc.connections(kind='inet')
        if connections:
            outbound_conns = [c for c in connections if c.status == 'ESTABLISHED' and c.raddr]
            if outbound_conns:
                reasons.append(f"Has {len(outbound_conns)} active outbound connection(s)")
                score += SCORES['OUTBOUND_NETWORK']
            
            conn_count = len(connections)
            if conn_count > process_net_baseline.get(pid, 0) + ABNORMAL_NET_CONNS:
                reasons.append("Abnormal connection growth")
                score += SCORES['ABNORMAL_NET_GROWTH']
            process_net_baseline[pid] = conn_count

        # --- Final Score Update and AI Trigger ---
        
        if score > 30:
            
            # Check if it's a new or escalated alert for logging purposes
            is_new_alert = pid not in SUSPICIOUS_PROCESSES
            is_escalated = (pid in SUSPICIOUS_PROCESSES and score != SUSPICIOUS_PROCESSES[pid].get('score'))

            # Initialize or update the SUSPICIOUS_PROCESSES entry
            SUSPICIOUS_PROCESSES[pid] = {
                'pid': pid,
                'name': name,
                'username': username,
                'score': score,
                'reasons': list(set(reasons)),
                'ai_summary': SUSPICIOUS_PROCESSES[pid].get('ai_summary', 'Awaiting AI Triage...') if not is_new_alert else 'Awaiting AI Triage...'
            }
            ALL_PROCESS_CACHE[pid]['score'] = score

            if is_new_alert or is_escalated:
                 print(f"================================================================")
                 print(f"[ALERT UPDATE] PID {pid} ({name}) - Total Score: {score}")
                 
            # AI Triage Trigger: If the score hits the alert threshold (90) and it's not already being analyzed
            if score >= ALERT_THRESHOLD and pid not in SUSPICIOUS_PROCESSES_AI_PENDING:
                SUSPICIOUS_PROCESSES_AI_PENDING.add(pid)
                # Launch AI worker thread
                t = threading.Thread(
                    target=ai_triage_worker, 
                    args=(pid, name, SUSPICIOUS_PROCESSES[pid]['reasons'], score)
                )
                t.daemon = True # Allows thread to exit when main program exits
                t.start()
                
        else:
            # If score drops to 0, clear it from the suspicious list
            if pid in SUSPICIOUS_PROCESSES:
                print(f"[CLEAR] PID {pid} ({name}) score dropped to 0. Removing from alert list.")
                # Also remove from pending set if it was there
                if pid in SUSPICIOUS_PROCESSES_AI_PENDING:
                     SUSPICIOUS_PROCESSES_AI_PENDING.remove(pid)
                del SUSPICIOUS_PROCESSES[pid]
        
    except psutil.NoSuchProcess:
        # Process ended
        if pid in SUSPICIOUS_PROCESSES: del SUSPICIOUS_PROCESSES[pid]
        if pid in ALL_PROCESS_CACHE: del ALL_PROCESS_CACHE[pid] 
    except psutil.AccessDenied:
        if name not in ['System', 'System Idle Process']:
            print(f"[ERROR: ACCESS DENIED] Detector cannot read metrics for PID {pid} ({name}). Rerun Detector as Administrator!")
    except Exception as e:
        print(f"[GENERIC ERROR] Failed to analyze PID {pid} ({name}): {e}")


def monitoring_loop():
    print("Monitoring loop started in background thread...")
    while True:
        all_pids = psutil.pids()
        
        for pid in all_pids:
            if not psutil.pid_exists(pid): continue
            try:
                proc = psutil.Process(pid)
                analyze_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # Cleanup old PIDs from trackers
        current_pids = set(all_pids)
        for pid in list(suspicion_scores.keys()):
            if pid not in current_pids: del suspicion_scores[pid]
        
        time.sleep(3)


# --- Flask Web Routes ---

@app.route('/api/data')
def api_data():
    """Returns suspicious processes and top safe processes in real-time."""
    # 1. Suspicious Processes (Score > 0)
    sorted_suspicious = sorted(SUSPICIOUS_PROCESSES.values(), key=lambda x: x['score'], reverse=True)
    
    # CRUCIAL DEBUG LOG: Log the state right before sending to the browser
    if sorted_suspicious:
        # Log the latest AI summary state for the top alert
        top_alert = sorted_suspicious[0]
        summary_status = top_alert.get('ai_summary', 'N/A')
        print(f"[API RESPONSE] Sending {len(sorted_suspicious)} suspicious processes. Top Alert PID {top_alert['pid']} ({top_alert['name']}). Summary Status: {summary_status[:30]}...")

    # 2. Safe Processes (Score = 0). Sort by CPU usage to show active ones.
    safe_processes = [
        p for p in ALL_PROCESS_CACHE.values()
        if p['score'] == 0 and p['name'] not in ['System Idle Process', 'System']
    ]
    sorted_safe = sorted(safe_processes, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:5] # Top 5
    
    return jsonify({
        'suspicious': sorted_suspicious,
        'safe': sorted_safe
    })

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

# --- Embedded HTML/JS for the UI (Updated to show AI Summary) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-Enhanced Keylogger Detection Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0F172A; color: #E5E7EB; font-family: 'Inter', sans-serif; }
        .card { background-color: #1F2937; border-radius: 0.75rem; transition: all 0.3s; }
        .alert-high { border-left: 6px solid #F87171; } /* Red */
        .alert-med { border-left: 6px solid #FBBF24; } /* Amber */
        .alert-safe { border-left: 6px solid #34D399; } /* Green */
        .score-bar { height: 8px; border-radius: 4px; }
    </style>
</head>
<body class="p-4 md:p-8">
    <div class="max-w-7xl mx-auto">
        <h1 class="text-3xl font-extrabold text-white mb-2 border-b border-gray-700 pb-3">AI-Enhanced Keylogger Detector</h1>
        <p class="text-lg text-cyan-400 mb-6">Live Behavioral Analysis and Threat Triage</p>

        
        </div>

        <!-- SUSPICIOUS PROCESSES SECTION -->
        <h2 class="text-2xl font-bold text-red-400 mt-8 mb-4"> Suspicious Processes (Score > 0)</h2>
        <div id="suspicious-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <div id="suspicious-loading" class="text-gray-400 lg:col-span-3 italic">Monitoring... Please run the demo keylogger to see activity.</div>
        </div>

        <!-- SAFE PROCESSES SECTION -->
        <h2 class="text-2xl font-bold text-green-400 mt-12 mb-4"> Top Safe Processes (Score 0)</h2>
        <p class="text-sm text-gray-400 mb-4">Processes below are currently considered safe, sorted by CPU usage.</p>
        <div id="safe-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <!-- Safe process cards will be injected here -->
        </div>
    </div>
    
    <script>
        // Use a map to store the generated summary to avoid flickering if the fetch is delayed
        const summaryCache = new Map();

        function renderScoreBar(score) {
            let color = 'bg-gray-500';
            if (score >= 90) color = 'bg-red-500';
            else if (score >= 50) color = 'bg-yellow-500';
            else if (score > 0) color = 'bg-blue-500';
            
            return `
                <div class="w-full bg-gray-700 score-bar mb-2">
                    <div class="${color} score-bar" style="width: ${Math.min(score, 100)}%"></div>
                </div>
            `;
        }

        function createProcessCard(proc, isSafe) {
            // Update cache with the latest summary
            if (proc.ai_summary) {
                summaryCache.set(proc.pid, proc.ai_summary);
            } else if (!summaryCache.has(proc.pid)) {
                // Set initial pending state if it's high score and not yet analyzed
                if (proc.score >= 90) {
                     summaryCache.set(proc.pid, 'AI Triage Pending...');
                }
            }

            let scoreClass = 'alert-low';
            if (proc.score >= 90) scoreClass = 'alert-high';
            else if (proc.score >= 50) scoreClass = 'alert-med';
            else if (isSafe) scoreClass = 'alert-safe';

            let scoreDisplay = isSafe
                ? `<span class="text-lg font-bold text-green-400">SAFE</span>`
                : `<span class="text-2xl font-bold ${scoreClass.replace('alert-', 'text-')}">${proc.score}</span>`;

            let analysisHtml = '';

            if (!isSafe) {
                const currentSummary = summaryCache.get(proc.pid) || 'Awaiting AI Triage...';

                if (proc.score >= 90 && currentSummary.startsWith('Awaiting') || currentSummary.startsWith('AI Triage P')) {
                    // Show spinner for high score awaiting triage
                    analysisHtml = `
                        <p class="text-sm font-medium text-blue-400 mb-2 mt-4 flex items-center">
                            <svg class="animate-spin -ml-1 mr-2 h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                            </svg>
                            ${currentSummary}
                        </p>
                    `;
                } else if (currentSummary && currentSummary !== 'Awaiting AI Triage...') {
                    // Show the AI summary
                    analysisHtml = `
                        <p class="text-sm font-semibold text-gray-200 mt-4 mb-2">Threat Analyst Report:</p>
                        <p class="text-sm text-gray-300 italic whitespace-pre-wrap">${currentSummary}</p>
                    `;
                } else {
                    // Show technical reasons for scores < 90 or if AI is disabled
                    let reasonsHtml = proc.reasons.map(reason =>
                        `<li class="text-sm text-gray-300">${reason}</li>`
                    ).join('');
                    analysisHtml = `
                        <p class="text-sm font-medium text-gray-300 mb-2 mt-4">Technical Triggers:</p>
                        <ul class="list-disc list-inside space-y-1">
                            ${reasonsHtml}
                        </ul>
                    `;
                }
            } else {
                 analysisHtml = `
                    <p class="text-xs text-gray-500 mt-4">
                        Normal system activity. CPU: ${proc.cpu_percent ? proc.cpu_percent.toFixed(2) : 'N/A'}%
                    </p>
                `;
            }


            return `
                <div class="card p-5 ${scoreClass} hover:shadow-2xl transition-shadow">
                    <div class="flex justify-between items-start mb-2">
                        <span class="text-xl font-semibold text-white truncate max-w-[80%]">${proc.name}</span>
                        ${scoreDisplay}
                    </div>
                    <div class="mb-3 text-sm text-gray-400 flex justify-between">
                        <span>PID: ${proc.pid}</span>
                        <span>User: ${proc.username}</span>
                    </div>

                    ${renderScoreBar(proc.score || 0)}
                    
                    ${analysisHtml}
                </div>
            `;
        }

        async function fetchProcessData() {
            try {
                const response = await fetch('/api/data');
                const data = await response.json();
                
                const suspiciousGrid = document.getElementById('suspicious-grid');
                const safeGrid = document.getElementById('safe-grid');
                const suspiciousLoading = document.getElementById('suspicious-loading');
                
                // --- 1. Render Suspicious Processes ---
                if (data.suspicious.length === 0) {
                    suspiciousLoading.style.display = "block";
                    suspiciousGrid.innerHTML = `<div id="suspicious-loading" class="text-gray-400 lg:col-span-3 italic">Monitoring... Please run the demo keylogger to see activity.</div>`;
                } else {
                    suspiciousLoading.style.display = "none";
                    suspiciousGrid.innerHTML = "";
                    data.suspicious.forEach(proc => {
                        suspiciousGrid.innerHTML += createProcessCard(proc, false);
                    });
                }
                
                // --- 2. Render Safe Processes ---
                safeGrid.innerHTML = "";
                data.safe.forEach(proc => {
                    safeGrid.innerHTML += createProcessCard(proc, true);
                });
                
            } catch (error) {
                console.error("Error fetching data:", error);
            }
        }
        
        // Fetch data every 3 seconds
        setInterval(fetchProcessData, 3000);
        fetchProcessData();
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()
    app.run(host='0.0.0.0', port=5000)
