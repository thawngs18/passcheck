// Formula Password Checker - International Standard Algorithm
class FormulaPasswordChecker {
  constructor() {
    this.passwordInput = document.getElementById("passwordInput");
    this.togglePassword = document.getElementById("togglePassword");
    this.quickAnalysis = document.getElementById("quickAnalysis");
    this.modalOverlay = document.getElementById("modalOverlay");
    this.detailBtn = document.getElementById("detailBtn");
    this.closeBtn = document.getElementById("closeBtn");

    // History elements
    this.historySection = document.getElementById("historySection");
    this.clearHistoryBtn = document.getElementById("clearHistoryBtn");
    this.historyList = document.getElementById("historyList");
    this.historyCount = document.getElementById("historyCount");

    // Quick analysis elements
    this.meterFill = document.getElementById("meterFill");
    this.strengthLabel = document.getElementById("strengthLabel");
    this.entropyDisplay = document.getElementById("entropyDisplay");
    this.crackTimeValue = document.getElementById("crackTimeValue");

    // Character analysis elements
    this.lengthValue = document.getElementById("lengthValue");
    this.lowercaseValue = document.getElementById("lowercaseValue");
    this.uppercaseValue = document.getElementById("uppercaseValue");
    this.numbersValue = document.getElementById("numbersValue");
    this.symbolsValue = document.getElementById("symbolsValue");
    this.uniqueValue = document.getElementById("uniqueValue");

    // Security analysis elements
    this.breachValue = document.getElementById("breachValue");
    this.patternValue = document.getElementById("patternValue");

    // Recommendations
    this.recommendationList = document.getElementById("recommendationList");

    // Store analysis data
    this.currentAnalysis = null;
    this.history = this.loadHistory();

    this.init();

    // Always show history section and load history on startup
    this.updateHistoryDisplay();
  }

  init() {
    this.passwordInput.addEventListener("input", () => this.analyzePassword());
    this.togglePassword.addEventListener("click", () =>
      this.togglePasswordVisibility()
    );
    this.detailBtn.addEventListener("click", () => this.showModal());
    this.closeBtn.addEventListener("click", () => this.hideModal());
    this.modalOverlay.addEventListener("click", (e) => {
      if (e.target === this.modalOverlay) {
        this.hideModal();
      }
    });

    // History event listeners
    this.clearHistoryBtn.addEventListener("click", () => this.clearHistory());

    // Debounce for better performance
    this.debounceAnalyze = this.debounce(() => this.analyzePassword(), 300);
    this.passwordInput.addEventListener("input", this.debounceAnalyze);
  }

  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  togglePasswordVisibility() {
    const type =
      this.passwordInput.getAttribute("type") === "password"
        ? "text"
        : "password";
    this.passwordInput.setAttribute("type", type);

    const icon = this.togglePassword.querySelector("i");
    icon.classList.toggle("fa-eye");
    icon.classList.toggle("fa-eye-slash");
  }

  async analyzePassword() {
    const password = this.passwordInput.value;

    if (!password) {
      this.hideQuickAnalysis();
      return;
    }

    this.showQuickAnalysis();

    try {
      // Gọi API Flask để phân tích mật khẩu
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password: password }),
      });

      if (!response.ok) {
        throw new Error("Lỗi kết nối API");
      }

      const analysis = await response.json();

      // Augment with local zxcvbn name-only detection so UI can reflect it
      try {
        const nameDetected = this.hasNameFromZxcvbn(password);
        analysis.patternAnalysis = analysis.patternAnalysis || {};
        if (nameDetected) {
          analysis.patternAnalysis.hasNameZxcvbn = true;
          // Ensure hasAnyPattern reflects the name detection
          const values = Object.values(analysis.patternAnalysis);
          analysis.patternAnalysis.hasAnyPattern = values.some(
            (v) => v === true
          );

          // Add a recommendation if not already present
          if (Array.isArray(analysis.recommendations)) {
            const msg = "Tránh dùng tên người/họ trong mật khẩu";
            if (!analysis.recommendations.includes(msg)) {
              analysis.recommendations.push(msg);
            }
          }
        }
      } catch (_) {
        // Non-fatal: keep original API analysis if zxcvbn not available
      }

      // Store analysis data for modal (already augmented with local name check)
      this.currentAnalysis = analysis;

      // Update quick analysis UI only
      this.updateStrengthMeter(analysis.strengthLevel, analysis.entropy);
      this.updateCrackTime(analysis.crackTime);
    } catch (error) {
      console.error("Lỗi phân tích mật khẩu:", error);
      // Fallback to local analysis if API fails
      this.analyzePasswordLocal(password);
    }
  }

  analyzePasswordLocal(password) {
    // 1. Calculate entropy
    const entropy = this.calculateEntropy(password);

    // 2. Analyze character composition
    const charAnalysis = this.analyzeCharacters(password);

    // 3. Check for common patterns
    const patternAnalysis = this.analyzePatterns(password);

    // 4. Check for breaches (async)
    this.checkBreaches(password).then((breachAnalysis) => {
      // 5. Calculate strength level
      const strengthLevel = this.calculateStrengthLevel(
        entropy,
        patternAnalysis,
        breachAnalysis
      );

      // 6. Calculate crack time
      const crackTime = this.calculateCrackTime(
        entropy,
        patternAnalysis,
        breachAnalysis
      );

      // 7. Generate recommendations
      const recommendations = this.generateRecommendations(
        charAnalysis,
        patternAnalysis,
        breachAnalysis
      );

      // Store analysis data for modal
      this.currentAnalysis = {
        password: password,
        entropy,
        charAnalysis,
        patternAnalysis,
        breachAnalysis,
        strengthLevel,
        crackTime,
        recommendations,
      };

      // Update quick analysis UI only
      this.updateStrengthMeter(strengthLevel, entropy);
      this.updateCrackTime(crackTime);
    });
  }

  // Calculate Shannon entropy
  calculateEntropy(password) {
    const length = password.length;
    const charset = this.getCharsetSize(password);

    // Basic entropy = length * log2(charset)
    const basicEntropy = length * Math.log2(charset);

    // Calculate actual entropy based on character frequency
    const charFreq = {};
    for (let char of password) {
      charFreq[char] = (charFreq[char] || 0) + 1;
    }

    let shannonEntropy = 0;
    for (let char in charFreq) {
      const freq = charFreq[char] / length;
      shannonEntropy -= freq * Math.log2(freq);
    }

    // Return the lower value between theoretical and actual entropy
    return Math.min(basicEntropy, shannonEntropy * length);
  }

  getCharsetSize(password) {
    let charset = 0;
    if (/[a-z]/.test(password)) charset += 26;
    if (/[A-Z]/.test(password)) charset += 26;
    if (/[0-9]/.test(password)) charset += 10;
    if (/[^A-Za-z0-9]/.test(password)) charset += 32; // Special characters
    return charset || 1;
  }

  analyzeCharacters(password) {
    const length = password.length;
    const lowercase = (password.match(/[a-z]/g) || []).length;
    const uppercase = (password.match(/[A-Z]/g) || []).length;
    const numbers = (password.match(/[0-9]/g) || []).length;
    const symbols = (password.match(/[^A-Za-z0-9]/g) || []).length;
    const unique = new Set(password).size;

    return {
      length,
      lowercase,
      uppercase,
      numbers,
      symbols,
      unique,
      hasLowercase: lowercase > 0,
      hasUppercase: uppercase > 0,
      hasNumbers: numbers > 0,
      hasSymbols: symbols > 0,
    };
  }

  analyzePatterns(password) {
    const patterns = {
      isCommon: this.isCommonPassword(password),
      hasSequential: this.hasSequentialPattern(password),
      hasKeyboard: this.hasKeyboardPattern(password),
      hasDate: this.hasDatePattern(password),
      // Name-only detection via zxcvbn dictionaries (male/female/surnames)
      hasNameZxcvbn: this.hasNameFromZxcvbn(password),
      hasRepeated: this.hasRepeatedPattern(password),
      isTooShort: password.length < 8,
      isVeryShort: password.length < 6,
    };

    patterns.hasAnyPattern = Object.values(patterns).some(
      (value) => value === true
    );

    return patterns;
  }

  hasNameFromZxcvbn(password) {
    try {
      if (typeof zxcvbn !== "function") {
        console.warn("zxcvbn not loaded: name detection disabled");
        return false;
      }
      if (!password || password.length === 0) return false;

      const nameDicts = new Set([
        "male_names",
        "female_names",
        "surnames",
        "names",
      ]);

      const containsName = (text) => {
        const res = zxcvbn(text);
        if (!res || !Array.isArray(res.sequence)) return false;
        for (const m of res.sequence) {
          if (
            m &&
            m.pattern === "dictionary" &&
            m.dictionary_name &&
            nameDicts.has(m.dictionary_name)
          ) {
            return true;
          }
        }
        return false;
      };

      // Check full password
      if (containsName(password)) return true;

      // Also check alphabetic-only segments (e.g., "alex" in "alex123.alo")
      const alphaSegments = password.match(/[A-Za-z]{3,}/g) || [];
      for (const seg of alphaSegments) {
        if (containsName(seg)) return true;
      }
      return false;
    } catch (e) {
      return false;
    }
  }

  isCommonPassword(password) {
    const commonPasswords = [
      "password",
      "123456",
      "123456789",
      "qwerty",
      "abc123",
      "password123",
      "admin",
      "letmein",
      "welcome",
      "monkey",
      "111111",
      "000000",
      "123123",
      "654321",
      "1234567890",
      "iloveyou",
      "dragon",
      "master",
      "hello",
      "login",
      "princess",
      "qwertyuiop",
      "solo",
      "passw0rd",
      "starwars",
    ];

    return (
      commonPasswords.includes(password.toLowerCase()) ||
      commonPasswords.includes(password)
    );
  }

  hasSequentialPattern(password) {
    const sequentialPatterns = [
      /012|123|234|345|456|567|678|789|890/,
      /abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz/i,
      /qwe|wer|ert|rty|tyu|yui|uio|iop/i,
      /asd|sdf|dfg|fgh|ghj|hjk|jkl/i,
      /zxc|xcv|cvb|vbn|bnm/i,
    ];

    return sequentialPatterns.some((pattern) => pattern.test(password));
  }

  hasKeyboardPattern(password) {
    const keyboardPatterns = [
      /qwerty/i,
      /asdf/i,
      /zxcv/i,
      /qwertyuiop/i,
      /asdfghjkl/i,
      /zxcvbnm/i,
      /1qaz2wsx/i,
      /qazwsxedcrfvtgbyhnujmikolp/i,
    ];

    return keyboardPatterns.some((pattern) => pattern.test(password));
  }

  hasDatePattern(password) {
    const datePatterns = [
      /\d{8}/, // 8 consecutive digits
      /\d{4}[-\/]\d{2}[-\/]\d{2}/, // YYYY-MM-DD or YYYY/MM/DD
      /\d{2}[-\/]\d{2}[-\/]\d{4}/, // MM-DD-YYYY or MM/DD/YYYY
      /\d{2}\d{2}\d{4}/, // MMDDYYYY
      /\d{4}\d{2}\d{2}/, // YYYYMMDD
    ];

    return datePatterns.some((pattern) => pattern.test(password));
  }

  // ❌ BỎ HOÀN TOÀN FUNCTION hasNamePattern
  // hasNamePattern(password) {
  //   return false; // Không kiểm tra tên nữa
  // }

  hasRepeatedPattern(password) {
    const repeatedPatterns = [
      /(.)\1{3,}/, // Same character repeated 4+ times
      /(..)\1{2,}/, // Same 2-char pattern repeated 3+ times
      /(...)\1{1,}/, // Same 3-char pattern repeated 2+ times
    ];

    return repeatedPatterns.some((pattern) => pattern.test(password));
  }

  async checkBreaches(password) {
    // First check against common passwords
    const isCommon = this.isCommonPassword(password);
    if (isCommon) {
      return {
        isBreached: true,
        status: "danger",
        message: "Mật khẩu phổ biến - dễ bị rò rỉ!",
        count: "Nhiều lần",
      };
    }

    try {
      // Use HaveIBeenPwned API v3 (k-anonymity model)
      const hash = await this.sha1Hash(password);
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5).toUpperCase();

      const response = await fetch(
        `https://api.pwnedpasswords.com/range/${prefix}`
      );

      if (!response.ok) {
        throw new Error("API request failed");
      }

      const data = await response.text();
      const hashes = data.split("\n");

      for (const line of hashes) {
        if (line.startsWith(suffix)) {
          const count = parseInt(line.split(":")[1]);
          return {
            isBreached: true,
            status: "danger",
            message: `Mật khẩu đã bị rò rỉ ${count.toLocaleString()} lần!`,
            count: count.toLocaleString(),
          };
        }
      }

      return {
        isBreached: false,
        status: "safe",
        message: "Không tìm thấy rò rỉ",
        count: "0",
      };
    } catch (error) {
      console.warn("HaveIBeenPwned API error:", error);
      // Fallback to common password check
      return {
        isBreached: false,
        status: "warning",
        message: "Không thể kiểm tra rò rỉ (lỗi kết nối)",
        count: "?",
      };
    }
  }

  async sha1Hash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest("SHA-1", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return hashHex.toUpperCase();
  }

  calculateStrengthLevel(entropy, patternAnalysis, breachAnalysis) {
    if (breachAnalysis.isBreached) {
      return { level: "very-weak", score: 5 };
    }

    if (patternAnalysis.isVeryShort) {
      return { level: "very-weak", score: 10 };
    }

    if (patternAnalysis.hasAnyPattern) {
      if (entropy < 20) return { level: "very-weak", score: 15 };
      if (entropy < 30) return { level: "weak", score: 25 };
      return { level: "fair", score: 40 };
    }

    if (entropy < 28) return { level: "very-weak", score: 20 };
    if (entropy < 36) return { level: "weak", score: 35 };
    if (entropy < 60) return { level: "fair", score: 60 };
    if (entropy < 128) return { level: "good", score: 85 };
    return { level: "strong", score: 100 };
  }

  calculateCrackTime(entropy, patternAnalysis, breachAnalysis) {
    if (breachAnalysis.isBreached || patternAnalysis.isVeryShort) {
      return "Dưới 1 giây";
    }

    if (patternAnalysis.hasAnyPattern) {
      if (entropy < 20) return "Vài giây";
      if (entropy < 30) return "Vài phút";
      return "Vài giờ";
    }

    const guesses = Math.pow(2, entropy);
    const attemptsPerSecond = Math.pow(10, 10); // 10 billion guesses per second
    const seconds = guesses / (2 * attemptsPerSecond);

    return this.formatTime(seconds);
  }

  formatTime(seconds) {
    if (seconds < 1) return "Dưới 1 giây";
    if (seconds < 60) return `${Math.round(seconds)} giây`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} phút`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} giờ`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} ngày`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} năm`;
    return `${Math.round(seconds / 3153600000)} thiên niên kỷ`;
  }

  generateRecommendations(charAnalysis, patternAnalysis, breachAnalysis) {
    const recommendations = [];

    if (breachAnalysis.isBreached) {
      recommendations.push(
        "Thay đổi mật khẩu ngay lập tức - mật khẩu đã bị rò rỉ"
      );
    }

    if (patternAnalysis.isVeryShort) {
      recommendations.push("Tăng độ dài mật khẩu lên ít nhất 8 ký tự");
    }

    if (patternAnalysis.hasSequential) {
      recommendations.push("Tránh sử dụng chuỗi ký tự liên tiếp (123, abc)");
    }

    if (patternAnalysis.hasKeyboard) {
      recommendations.push("Tránh sử dụng pattern bàn phím (qwerty, asdf)");
    }

    if (patternAnalysis.hasDate) {
      recommendations.push("Tránh sử dụng ngày tháng trong mật khẩu");
    }

    // Name-only check via zxcvbn
    if (patternAnalysis.hasNameZxcvbn) {
      recommendations.push("Tránh dùng tên người/họ trong mật khẩu");
    }

    if (patternAnalysis.hasRepeated) {
      recommendations.push("Tránh lặp lại ký tự hoặc pattern");
    }

    if (!charAnalysis.hasLowercase) {
      recommendations.push("Thêm chữ thường (a-z)");
    }

    if (!charAnalysis.hasUppercase) {
      recommendations.push("Thêm chữ hoa (A-Z)");
    }

    if (!charAnalysis.hasNumbers) {
      recommendations.push("Thêm số (0-9)");
    }

    if (!charAnalysis.hasSymbols) {
      recommendations.push("Thêm ký tự đặc biệt (!@#$%^&*)");
    }

    if (charAnalysis.length < 12) {
      recommendations.push("Tăng độ dài lên ít nhất 12 ký tự");
    }

    if (charAnalysis.unique < charAnalysis.length * 0.7) {
      recommendations.push("Tăng tính đa dạng ký tự");
    }

    return recommendations;
  }

  updateStrengthMeter(strengthLevel, entropy) {
    this.meterFill.className = `meter-fill ${strengthLevel.level}`;
    this.entropyDisplay.textContent = `${Math.round(entropy)} bits`;

    const labels = {
      "very-weak": "RẤT YẾU",
      weak: "YẾU",
      fair: "TRUNG BÌNH",
      good: "TỐT",
      strong: "MẠNH",
    };

    this.strengthLabel.textContent = labels[strengthLevel.level] || "RẤT YẾU";
  }

  updateCharacterAnalysis(charAnalysis) {
    this.lengthValue.textContent = charAnalysis.length;
    this.lowercaseValue.textContent = charAnalysis.lowercase;
    this.uppercaseValue.textContent = charAnalysis.uppercase;
    this.numbersValue.textContent = charAnalysis.numbers;
    this.symbolsValue.textContent = charAnalysis.symbols;
    this.uniqueValue.textContent = charAnalysis.unique;

    // Update character item validity
    document
      .getElementById("lengthItem")
      .classList.toggle("valid", charAnalysis.length >= 8);
    document
      .getElementById("lowercaseItem")
      .classList.toggle("valid", charAnalysis.hasLowercase);
    document
      .getElementById("uppercaseItem")
      .classList.toggle("valid", charAnalysis.hasUppercase);
    document
      .getElementById("numbersItem")
      .classList.toggle("valid", charAnalysis.hasNumbers);
    document
      .getElementById("symbolsItem")
      .classList.toggle("valid", charAnalysis.hasSymbols);
    document
      .getElementById("uniqueItem")
      .classList.toggle(
        "valid",
        charAnalysis.unique >= charAnalysis.length * 0.7
      );
  }

  updateSecurityAnalysis(breachAnalysis, patternAnalysis) {
    this.breachValue.textContent = breachAnalysis.message;
    this.breachValue.className = `security-value ${breachAnalysis.status}`;

    if (patternAnalysis.hasAnyPattern) {
      this.patternValue.textContent = "Phát hiện pattern dễ đoán";
      this.patternValue.className = "security-value warning";
    } else {
      this.patternValue.textContent = "Không có pattern dễ đoán";
      this.patternValue.className = "security-value safe";
    }
  }

  updateCrackTime(crackTime) {
    this.crackTimeValue.textContent = crackTime;
  }

  updateRecommendations(recommendations) {
    this.recommendationList.innerHTML = "";

    if (recommendations.length === 0) {
      const li = document.createElement("li");
      li.textContent = "Mật khẩu của bạn đã đạt tiêu chuẩn bảo mật cao!";
      li.style.color = "#00ff00";
      this.recommendationList.appendChild(li);
    } else {
      recommendations.forEach((rec) => {
        const li = document.createElement("li");
        li.textContent = rec;
        this.recommendationList.appendChild(li);
      });
    }
  }

  showQuickAnalysis() {
    this.quickAnalysis.style.display = "block";
  }

  hideQuickAnalysis() {
    this.quickAnalysis.style.display = "none";
  }

  showModal() {
    if (!this.currentAnalysis) return;

    // Save to history when viewing details
    this.saveToHistory(this.currentAnalysis.password, this.currentAnalysis);

    this.modalOverlay.style.display = "flex";
    document.body.style.overflow = "hidden";

    // Update modal content with stored analysis
    this.updateCharacterAnalysis(this.currentAnalysis.charAnalysis);
    this.updateSecurityAnalysis(
      this.currentAnalysis.breachAnalysis,
      this.currentAnalysis.patternAnalysis
    );
    this.updateRecommendations(this.currentAnalysis.recommendations);
  }

  hideModal() {
    this.modalOverlay.style.display = "none";
    document.body.style.overflow = "auto";
  }

  // History functions
  loadHistory() {
    const history = localStorage.getItem("passwordHistory");
    return history ? JSON.parse(history) : [];
  }

  saveHistory() {
    localStorage.setItem("passwordHistory", JSON.stringify(this.history));
  }

  saveToHistory(password, analysis) {
    // Check if password already exists in history
    const existingIndex = this.history.findIndex(
      (item) => item.password === password
    );

    const historyItem = {
      password: password,
      timestamp: new Date().toISOString(),
      entropy: analysis.entropy,
      strengthLevel: analysis.strengthLevel,
      crackTime: analysis.crackTime,
      charAnalysis: analysis.charAnalysis,
      patternAnalysis: analysis.patternAnalysis,
      breachAnalysis: analysis.breachAnalysis,
      recommendations: analysis.recommendations,
    };

    if (existingIndex !== -1) {
      // Update existing entry
      this.history[existingIndex] = historyItem;
    } else {
      // Add new entry at the beginning
      this.history.unshift(historyItem);

      // Limit history to 50 items
      if (this.history.length > 50) {
        this.history = this.history.slice(0, 50);
      }
    }

    this.saveHistory();

    // Update history display after saving
    this.updateHistoryDisplay();
  }

  updateHistoryDisplay() {
    this.historyCount.textContent = `Số lượng: ${this.history.length} mật khẩu`;

    // Always show history section
    this.historySection.style.display = "block";

    this.historyList.innerHTML = "";

    if (this.history.length === 0) {
      const emptyDiv = document.createElement("div");
      emptyDiv.className = "history-empty";
      emptyDiv.innerHTML = `
        <div style="text-align: center; padding: 40px; color: #666;">
          <i class="fas fa-history" style="font-size: 48px; margin-bottom: 20px; opacity: 0.5;"></i>
          <p>Chưa có lịch sử mật khẩu</p>
        </div>
      `;
      this.historyList.appendChild(emptyDiv);
      return;
    }

    this.history.forEach((item, index) => {
      const historyItem = document.createElement("div");
      historyItem.className = "history-item";
      historyItem.innerHTML = `
        <div class="history-item-header">
          <div class="history-password">${this.maskPassword(
            item.password
          )}</div>
          <div class="history-time">${this.formatTimeAgo(item.timestamp)}</div>
        </div>
        <div class="history-strength">
          <div class="history-strength-bar">
            <div class="history-strength-fill ${
              item.strengthLevel.level
            }"></div>
          </div>
          <div class="history-strength-label">${this.getStrengthLabel(
            item.strengthLevel.level
          )}</div>
        </div>
        <div class="history-details">
          <span class="history-entropy">${Math.round(item.entropy)} bits</span>
          <span class="history-crack-time">${item.crackTime}</span>
        </div>
        <div class="history-actions">
          <button class="history-view-btn" onclick="event.stopPropagation(); window.passwordChecker.viewHistoryDetail(${index})">
            <i class="fas fa-eye"></i> Xem
          </button>
          <button class="history-delete-btn" onclick="event.stopPropagation(); window.passwordChecker.deleteHistoryItem(${index})">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      `;

      historyItem.addEventListener("click", () => this.loadHistoryItem(item));
      this.historyList.appendChild(historyItem);
    });
  }

  maskPassword(password) {
    if (password.length <= 4) {
      return "*".repeat(password.length);
    }
    return (
      password.substring(0, 2) +
      "*".repeat(password.length - 4) +
      password.substring(password.length - 2)
    );
  }

  formatTimeAgo(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;

    if (diff < 60000) {
      // Less than 1 minute
      return "Vừa xong";
    } else if (diff < 3600000) {
      // Less than 1 hour
      return `${Math.floor(diff / 60000)} phút trước`;
    } else if (diff < 86400000) {
      // Less than 1 day
      return `${Math.floor(diff / 3600000)} giờ trước`;
    } else {
      return date.toLocaleDateString("vi-VN");
    }
  }

  getStrengthLabel(level) {
    const labels = {
      "very-weak": "RẤT YẾU",
      weak: "YẾU",
      fair: "TRUNG BÌNH",
      good: "TỐT",
      strong: "MẠNH",
    };
    return labels[level] || "RẤT YẾU";
  }

  loadHistoryItem(item) {
    // Load password into input
    this.passwordInput.value = item.password;
    this.passwordInput.dispatchEvent(new Event("input"));
  }

  viewHistoryDetail(index) {
    const item = this.history[index];

    // Set current analysis
    this.currentAnalysis = {
      password: item.password,
      entropy: item.entropy,
      charAnalysis: item.charAnalysis,
      patternAnalysis: item.patternAnalysis,
      breachAnalysis: item.breachAnalysis,
      strengthLevel: item.strengthLevel,
      crackTime: item.crackTime,
      recommendations: item.recommendations,
    };

    // Show detail modal without saving to history again
    this.modalOverlay.style.display = "flex";
    document.body.style.overflow = "hidden";

    // Update modal content with stored analysis
    this.updateCharacterAnalysis(this.currentAnalysis.charAnalysis);
    this.updateSecurityAnalysis(
      this.currentAnalysis.breachAnalysis,
      this.currentAnalysis.patternAnalysis
    );
    this.updateRecommendations(this.currentAnalysis.recommendations);
  }

  deleteHistoryItem(index) {
    if (confirm("Bạn có chắc chắn muốn xóa mật khẩu này khỏi lịch sử?")) {
      this.history.splice(index, 1);
      this.saveHistory();
      this.updateHistoryDisplay();
    }
  }

  clearHistory() {
    if (confirm("Bạn có chắc chắn muốn xóa toàn bộ lịch sử?")) {
      this.history = [];
      this.saveHistory();
      this.updateHistoryDisplay();
    }
  }
}

// Initialize the application
document.addEventListener("DOMContentLoaded", () => {
  window.passwordChecker = new FormulaPasswordChecker();

  console.log("Formula Password Checker initialized successfully!");
  console.log("Features:");
  console.log("- Shannon entropy calculation");
  console.log("- International standard algorithm");
  console.log("- Pattern detection (Sequential, Keyboard, Date, Repeated)");
  console.log("- Breach checking via HaveIBeenPwned API");
  console.log("- Real-time analysis");
  console.log("- Password history tracking");
  console.log("✅ Name-only detection via zxcvbn ENABLED");
});

// Export for potential module use
if (typeof module !== "undefined" && module.exports) {
  module.exports = { FormulaPasswordChecker };
}

// AI Chat Functionality
class AIChat {
  constructor() {
    this.chatContainer = document.getElementById("chatContainer");
    this.chatToggleBtn = document.getElementById("chatToggleBtn");
    this.chatMessages = document.getElementById("chatMessages");
    this.chatInput = document.getElementById("chatInput");
    this.sendChatBtn = document.getElementById("sendChatBtn");
    this.quickActionBtns = document.querySelectorAll(".quick-action-btn");

    this.isOpen = false;
    this.isTyping = false;
    this.conciseMode = false; // AI đã trả lời ngắn gọn rồi

    this.init();
  }

  init() {
    // Toggle chat
    this.chatToggleBtn.addEventListener("click", () => this.toggleChat());

    // Send message
    this.sendChatBtn.addEventListener("click", () => this.sendMessage());
    this.chatInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        this.sendMessage();
      }
    });

    // Quick actions
    this.quickActionBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        const message = btn.getAttribute("data-message");
        this.chatInput.value = message;
        this.sendMessage();
      });
    });
  }

  toggleChat() {
    const wrapper = document.getElementById("aiChatSection");
    if (wrapper) {
      this.isOpen = !this.isOpen;
      wrapper.classList.toggle("open", this.isOpen);
    } else {
      this.isOpen = !this.isOpen;
    }

    if (this.chatContainer) {
      this.chatContainer.style.display = this.isOpen ? "flex" : "none";
    }

    if (this.isOpen && this.chatInput) {
      this.chatInput.focus();
      this.scrollToBottom();
    }
  }

  async sendMessage() {
    const message = this.chatInput.value.trim();
    if (!message || this.isTyping) return;

    // Add user message to chat
    this.addMessage(message, "user");
    this.chatInput.value = "";

    // Show typing indicator
    this.showTypingIndicator();

    try {
      // Get current password context if available
      const passwordContext = this.getPasswordContext();

      // Send to AI API
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: message,
          password_context: passwordContext,
        }),
      });

      const data = await response.json();

      // Hide typing indicator
      this.hideTypingIndicator();

      if (data.success) {
        // Add AI response to chat (AI đã trả lời ngắn gọn từ backend)
        this.addMessage(data.response, "ai");
      } else {
        this.addMessage(`Xin lỗi, có lỗi xảy ra: ${data.error}`, "ai");
      }
    } catch (error) {
      console.error("Chat error:", error);
      this.hideTypingIndicator();
      this.addMessage(
        "Xin lỗi, tôi không thể kết nối đến AI. Vui lòng thử lại sau.",
        "ai"
      );
    }
  }

  addMessage(content, sender) {
    const messageDiv = document.createElement("div");
    messageDiv.className = `chat-message ${sender}-message`;

    const avatar = document.createElement("div");
    avatar.className = "message-avatar";
    avatar.innerHTML =
      sender === "ai"
        ? '<i class="fas fa-robot"></i>'
        : '<i class="fas fa-user"></i>';

    const messageContent = document.createElement("div");
    messageContent.className = "message-content";

    // Format message content (support basic HTML)
    messageContent.innerHTML = this.formatMessage(content);

    messageDiv.appendChild(avatar);
    messageDiv.appendChild(messageContent);

    this.chatMessages.appendChild(messageDiv);
    this.scrollToBottom();
  }

  formatMessage(content) {
    // Convert line breaks to <br>
    content = content.replace(/\n/g, "<br>");

    // Convert **text** to <strong>text</strong>
    content = content.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

    // Convert *text* to <em>text</em>
    content = content.replace(/\*(.*?)\*/g, "<em>$1</em>");

    // Convert - item to <li>item</li>
    content = content.replace(/^- (.+)$/gm, "<li>$1</li>");

    // Wrap consecutive <li> in <ul>
    content = content.replace(/(<li>.*<\/li>)/gs, "<ul>$1</ul>");

    return content;
  }

  showTypingIndicator() {
    this.isTyping = true;
    this.sendChatBtn.disabled = true;

    const typingDiv = document.createElement("div");
    typingDiv.className = "chat-message ai-message typing-indicator";
    typingDiv.id = "typingIndicator";

    typingDiv.innerHTML = `
      <div class="message-avatar">
        <i class="fas fa-robot"></i>
      </div>
      <div class="message-content">
        <div class="typing-indicator">
         đang suy nghĩ
          <div class="typing-dots">
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
            <div class="typing-dot"></div>
          </div>
        </div>
      </div>
    `;

    this.chatMessages.appendChild(typingDiv);
    this.scrollToBottom();
  }

  hideTypingIndicator() {
    this.isTyping = false;
    this.sendChatBtn.disabled = false;

    const typingIndicator = document.getElementById("typingIndicator");
    if (typingIndicator) {
      typingIndicator.remove();
    }
  }

  scrollToBottom() {
    this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
  }

  getPasswordContext() {
    // Get current password analysis data if available
    if (window.passwordChecker && window.passwordChecker.currentAnalysis) {
      const analysis = window.passwordChecker.currentAnalysis;
      return {
        length: analysis.charAnalysis?.length || 0,
        entropy: Math.round(analysis.entropy || 0),
        strength: analysis.strengthLevel?.level || "unknown",
        crack_time: analysis.crackTime || "unknown",
        issues: this.getPasswordIssues(analysis),
      };
    }
    return null;
  }

  getPasswordIssues(analysis) {
    const issues = [];

    if (analysis.patternAnalysis?.hasAnyPattern) {
      issues.push("Có pattern dễ đoán");
    }

    if (analysis.breachAnalysis?.isBreached) {
      issues.push("Mật khẩu đã bị rò rỉ");
    }

    if (analysis.charAnalysis?.length < 8) {
      issues.push("Mật khẩu quá ngắn");
    }

    if (!analysis.charAnalysis?.hasUppercase) {
      issues.push("Thiếu chữ hoa");
    }

    if (!analysis.charAnalysis?.hasLowercase) {
      issues.push("Thiếu chữ thường");
    }

    if (!analysis.charAnalysis?.hasNumbers) {
      issues.push("Thiếu số");
    }

    if (!analysis.charAnalysis?.hasSymbols) {
      issues.push("Thiếu ký tự đặc biệt");
    }

    return issues.length > 0 ? issues.join(", ") : "Không có vấn đề";
  }
}

// Initialize AI Chat when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  // Initialize password checker first
  if (!window.passwordChecker) {
    window.passwordChecker = new FormulaPasswordChecker();
  }

  // Initialize AI Chat
  window.aiChat = new AIChat();

  console.log("AI Chat initialized successfully!");
});
