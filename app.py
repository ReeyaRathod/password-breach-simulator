from flask import Flask, render_template, request
import math
import hashlib

app = Flask(__name__)

# Common weak passwords list for breach checking
COMMON_PASSWORDS = ["123456", "password", "123456789", "123456123", "qwerty", "admin", "welcome", "111111", "iloveyou"]

def calculate_entropy(password):
    if not password:
        return 0, 0
    
    charset_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_digit: charset_size += 10
    if has_special: charset_size += 32
    
    if charset_size == 0:
        return 0, 0
        
    # Entropy formula: L * log2(R)
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2), charset_size

def estimate_crack_time(entropy):
    if entropy == 0:
        return "Instant"
    
    # Assuming an attacker can test 10 billion hashes per second (GPU rig)
    guesses_per_second = 10_000_000_000
    total_combinations = 2 ** entropy
    seconds = total_combinations / guesses_per_second / 2 # average attempts = half
    
    if seconds < 1:
        return "Instant (< 1 second)"
    elif seconds < 60:
        return f"{round(seconds, 2)} seconds"
    elif seconds < 3600:
        return f"{round(seconds / 60, 1)} minutes"
    elif seconds < 86400:
        return f"{round(seconds / 3600, 1)} hours"
    elif seconds < 31536000:
        return f"{round(seconds / 86400, 1)} days"
    elif seconds < 31536000 * 1000:
        return f"{round(seconds / 31536000, 1)} years"
    else:
        return "Centuries (Extremely Strong)"

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        
        entropy, charset = calculate_entropy(password)
        crack_time = estimate_crack_time(entropy)
        
        # Strength classification
        if entropy < 28 or password in COMMON_PASSWORDS:
            strength = "Weak"
            color = "#f85149"
            width = "25%"
        elif entropy < 50:
            strength = "Moderate"
            color = "#d29922"
            width = "55%"
        elif entropy < 80:
            strength = "Strong"
            color = "#3fb950"
            width = "85%"
        else:
            strength = "Enterprise Grade"
            color = "#58a6ff"
            width = "100%"
            
        is_breached = password in COMMON_PASSWORDS
        
        # Generate Hashes
        md5_hash = hashlib.md5(password.encode()).hexdigest()
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        
        result = {
            "password": password,
            "entropy": entropy,
            "crack_time": crack_time,
            "strength": strength,
            "color": color,
            "width": width,
            "is_breached": is_breached,
            "md5": md5_hash,
            "sha256": sha256_hash
        }
        
    return render_template('index.html', result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
