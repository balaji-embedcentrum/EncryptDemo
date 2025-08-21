/**
 * Encryption Web Application - JavaScript Implementation
 * 
 * Implements functions defined in EncryptionFunctions.fun according to Sylang documentation:
 * - ValidateTextInput (line 14)
 * - GenerateCryptographicKey (line 23) 
 * - EncryptText (line 32)
 * - FormatEncryptedOutput (line 41)
 * - DisplayEncryptedResult (line 50)
 * - HandleEncryptionError (line 59)
 * - CopyToClipboardFunction (line 64)
 * - ClearSensitiveData (line 73)
 * - InitializeUserInterface (line 82)
 * - ProcessUserInput (line 91)
 * 
 * Security implementation follows:
 * - CryptoDecision.md (AES-GCM with Web Crypto API)
 * - InputValidation.md (comprehensive input validation)
 * - ThreatModel.md (security mitigations)
 * 
 * Requirements satisfied:
 * - REQ_FUNC_001: Text Input Processing
 * - REQ_FUNC_002: Encryption Processing  
 * - REQ_FUNC_003: Output Display
 * - REQ_FUNC_004: Error Handling
 * - REQ_PERF_001: Encryption Performance
 */

// Global state management
const AppState = {
    isProcessing: false,
    currentKey: null,
    lastEncryptedData: null
};

/**
 * Input Validator Class
 * Implements Function: ValidateTextInput (EncryptionFunctions.fun line 14)
 * Follows Requirement: REQ_FUNC_001 (EncryptionRequirements.req line 17)
 * Per InputValidation.md specifications
 */
class InputValidator {
    static validate(input) {
        const errors = [];
        
        // Length validation - per REQ_FUNC_001_1 (EncryptionRequirements.req line 23)
        if (input.length === 0) {
            errors.push('Input cannot be empty');
        }
        if (input.length > 10000) {
            errors.push(`Input too long: ${input.length}/10000 characters`);
        }
        
        // Character validation - per InputValidation.md character set restrictions
        const dangerousChars = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/;
        if (dangerousChars.test(input)) {
            errors.push('Input contains invalid control characters');
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors,
            sanitized: this.sanitize(input)
        };
    }
    
    /**
     * Sanitize input according to InputValidation.md
     * Implements Function: ValidateTextInput (EncryptionFunctions.fun line 14)
     * Follows Requirement: REQ_FUNC_001_2 (EncryptionRequirements.req line 35)
     */
    static sanitize(input) {
        return input
            .trim()
            .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control chars
            .replace(/&/g, '&amp;')   // Escape HTML entities per ThreatModel.md T-PRIV-01
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }
}

/**
 * Cryptographic Engine Class
 * Implements Functions: GenerateCryptographicKey, EncryptText (EncryptionFunctions.fun lines 23, 32)
 * Follows Requirements: REQ_FUNC_002, REQ_FUNC_002_1, REQ_FUNC_002_2 (EncryptionRequirements.req)
 * Per CryptoDecision.md specifications (AES-GCM 256-bit)
 */
class CryptographicEngine {
    /**
     * Generate 256-bit AES key using Web Crypto API
     * Implements Function: GenerateCryptographicKey (EncryptionFunctions.fun line 23)
     * Follows Requirement: REQ_FUNC_002_1 (EncryptionRequirements.req line 66)
     */
    static async generateKey() {
        try {
            // Generate 256-bit AES key as per CryptoDecision.md
            const key = await window.crypto.subtle.generateKey(
                {
                    name: "AES-GCM",
                    length: 256,
                },
                false, // not extractable - security best practice
                ["encrypt"]
            );
            return key;
        } catch (error) {
            throw new Error('Failed to generate cryptographic key');
        }
    }
    
    /**
     * Generate random initialization vector
     * Implements Function: EncryptText (EncryptionFunctions.fun line 32)
     * Follows Requirement: REQ_FUNC_002_2 (EncryptionRequirements.req line 76)
     */
    static generateIV() {
        // 96-bit IV as per CryptoDecision.md (recommended for GCM)
        return window.crypto.getRandomValues(new Uint8Array(12));
    }
    
    /**
     * Encrypt text using AES-GCM
     * Implements Function: EncryptText (EncryptionFunctions.fun line 32)
     * Follows Requirement: REQ_FUNC_002 (EncryptionRequirements.req line 58)
     */
    static async encryptText(plaintext, key, iv) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(plaintext);
            
            // Encrypt using AES-GCM as per CryptoDecision.md
            const encryptedData = await window.crypto.subtle.encrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                key,
                data
            );
            
            return encryptedData;
        } catch (error) {
            throw new Error('Encryption operation failed');
        }
    }
}

/**
 * Output Formatter Class
 * Implements Function: FormatEncryptedOutput (EncryptionFunctions.fun line 41)
 * Follows Requirement: REQ_FUNC_003 (EncryptionRequirements.req line 93)
 * Per CryptoDecision.md output format: Base64(IV || Ciphertext || AuthTag)
 */
class OutputFormatter {
    /**
     * Format encrypted data as base64 string
     * Implements Function: FormatEncryptedOutput (EncryptionFunctions.fun line 41)
     */
    static formatOutput(iv, encryptedData) {
        try {
            // Combine IV + encrypted data as per CryptoDecision.md format
            const combined = new Uint8Array(iv.length + encryptedData.byteLength);
            combined.set(new Uint8Array(iv), 0);
            combined.set(new Uint8Array(encryptedData), iv.length);
            
            // Convert to base64 for display
            return btoa(String.fromCharCode(...combined));
        } catch (error) {
            throw new Error('Failed to format encrypted output');
        }
    }
}

/**
 * UI Manager Class
 * Implements Functions: DisplayEncryptedResult, HandleEncryptionError (EncryptionFunctions.fun lines 50, 59)
 * Follows Requirements: REQ_FUNC_003, REQ_FUNC_004, REQ_USAB_001 (EncryptionRequirements.req)
 */
class UIManager {
    static elements = {};
    
    /**
     * Initialize UI elements and event handlers
     * Implements Function: InitializeUserInterface (EncryptionFunctions.fun line 82)
     * Enables Features: InputForm, Styling (EncryptionWebApp.fml lines 60, 71)
     */
    static initialize() {
        // Cache DOM elements
        this.elements = {
            inputText: document.getElementById('inputText'),
            outputText: document.getElementById('outputText'),
            encryptBtn: document.getElementById('encryptBtn'),
            clearBtn: document.getElementById('clearBtn'),
            copyBtn: document.getElementById('copyBtn'),
            charCount: document.getElementById('charCount'),
            validationStatus: document.getElementById('validationStatus'),
            statusArea: document.getElementById('statusArea'),
            errorMessage: document.getElementById('errorMessage'),
            errorText: document.getElementById('errorText'),
            successMessage: document.getElementById('successMessage'),
            successText: document.getElementById('successText'),
            copyStatus: document.getElementById('copyStatus'),
            processingIndicator: document.getElementById('processingIndicator')
        };
        
        // Set up event handlers
        this.setupEventHandlers();
        
        // Initial UI state
        this.updateCharacterCount();
        this.validateInput();
    }
    
    /**
     * Set up all event handlers
     */
    static setupEventHandlers() {
        // Input validation on change - implements real-time validation per InputValidation.md
        this.elements.inputText.addEventListener('input', () => {
            this.updateCharacterCount();
            this.validateInput();
            this.clearMessages();
        });
        
        // Encrypt button click
        this.elements.encryptBtn.addEventListener('click', () => {
            EncryptionController.processEncryption();
        });
        
        // Clear button click
        this.elements.clearBtn.addEventListener('click', () => {
            this.clearAll();
        });
        
        // Copy button click - implements Feature: CopyToClipboard (EncryptionWebApp.fml line 75)
        this.elements.copyBtn.addEventListener('click', () => {
            ClipboardManager.copyToClipboard();
        });
        
        // Prevent form submission on Enter key
        this.elements.inputText.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.ctrlKey && !this.elements.encryptBtn.disabled) {
                e.preventDefault();
                EncryptionController.processEncryption();
            }
        });
    }
    
    /**
     * Update character counter
     * Implements input length tracking per InputValidation.md
     */
    static updateCharacterCount() {
        const length = this.elements.inputText.value.length;
        this.elements.charCount.textContent = `${length} / 10,000 characters`;
        
        // Visual feedback for length limits
        if (length > 9000) {
            this.elements.charCount.className = 'text-sm text-red-500';
        } else if (length > 7000) {
            this.elements.charCount.className = 'text-sm text-yellow-600';
        } else {
            this.elements.charCount.className = 'text-sm text-gray-500';
        }
    }
    
    /**
     * Validate input and update UI
     * Implements Function: ValidateTextInput (EncryptionFunctions.fun line 14)
     */
    static validateInput() {
        const input = this.elements.inputText.value;
        const validation = InputValidator.validate(input);
        
        // Update validation status
        if (input.length === 0) {
            this.elements.validationStatus.textContent = '';
            this.elements.validationStatus.className = 'text-sm';
            this.elements.encryptBtn.disabled = true;
        } else if (validation.isValid) {
            this.elements.validationStatus.textContent = '✓ Valid input';
            this.elements.validationStatus.className = 'text-sm text-green-600';
            this.elements.encryptBtn.disabled = false;
        } else {
            this.elements.validationStatus.textContent = '✗ ' + validation.errors[0];
            this.elements.validationStatus.className = 'text-sm text-red-600';
            this.elements.encryptBtn.disabled = true;
        }
    }
    
    /**
     * Display encrypted result
     * Implements Function: DisplayEncryptedResult (EncryptionFunctions.fun line 50)
     * Follows Requirement: REQ_FUNC_003 (EncryptionRequirements.req line 93)
     * Enables Feature: OutputDisplay (EncryptionWebApp.fml line 65)
     */
    static displayResult(encryptedText) {
        this.elements.outputText.value = encryptedText;
        this.elements.copyBtn.disabled = false;
        this.showSuccess('Text encrypted successfully!');
    }
    
    /**
     * Handle and display errors
     * Implements Function: HandleEncryptionError (EncryptionFunctions.fun line 59)
     * Follows Requirement: REQ_FUNC_004 (EncryptionRequirements.req line 102)
     * Per ThreatModel.md - no sensitive details in error messages
     */
    static showError(message) {
        this.elements.statusArea.classList.remove('hidden');
        this.elements.errorMessage.classList.remove('hidden');
        this.elements.errorMessage.className = 'p-4 bg-red-50 border border-red-200 text-red-800 rounded-lg mb-4';
        this.elements.errorText.textContent = message;
        this.elements.successMessage.classList.add('hidden');
    }
    
    /**
     * Show success message
     * Implements user feedback per REQ_USAB_001 (EncryptionRequirements.req line 111)
     */
    static showSuccess(message) {
        this.elements.statusArea.classList.remove('hidden');
        this.elements.successMessage.classList.remove('hidden');
        this.elements.successText.textContent = message;
        this.elements.errorMessage.classList.add('hidden');
    }
    
    /**
     * Clear all messages
     */
    static clearMessages() {
        this.elements.statusArea.classList.add('hidden');
        this.elements.errorMessage.classList.add('hidden');
        this.elements.successMessage.classList.add('hidden');
        this.elements.copyStatus.textContent = '';
    }
    
    /**
     * Show processing indicator
     * Implements Requirement: REQ_USAB_001 (EncryptionRequirements.req line 111)
     */
    static showProcessing() {
        this.elements.processingIndicator.classList.remove('hidden');
        this.elements.encryptBtn.disabled = true;
        this.clearMessages();
    }
    
    /**
     * Hide processing indicator
     */
    static hideProcessing() {
        this.elements.processingIndicator.classList.add('hidden');
        this.validateInput(); // Re-enable button if input is valid
    }
    
    /**
     * Clear all fields and reset UI
     */
    static clearAll() {
        this.elements.inputText.value = '';
        this.elements.outputText.value = '';
        this.elements.copyBtn.disabled = true;
        this.updateCharacterCount();
        this.validateInput();
        this.clearMessages();
        
        // Clear sensitive data per Function: ClearSensitiveData (EncryptionFunctions.fun line 73)
        MemoryManager.clearSensitiveData();
        
        this.showSuccess('All data cleared');
    }
}

/**
 * Clipboard Manager Class
 * Implements Function: CopyToClipboardFunction (EncryptionFunctions.fun line 64)
 * Enables Feature: CopyToClipboard when config c_UserInterface_CopyToClipboard = 1
 * Per ThreatModel.md clipboard security considerations
 */
class ClipboardManager {
    static async copyToClipboard() {
        try {
            const text = UIManager.elements.outputText.value;
            if (!text) {
                UIManager.showError('No encrypted text to copy');
                return;
            }
            
            await navigator.clipboard.writeText(text);
            UIManager.elements.copyStatus.textContent = '✓ Copied to clipboard';
            UIManager.elements.copyStatus.className = 'text-sm text-green-600';
            
            // Clear status after 3 seconds
            setTimeout(() => {
                UIManager.elements.copyStatus.textContent = '';
            }, 3000);
            
            // Security warning per ThreatModel.md T-INFO-01
            setTimeout(() => {
                UIManager.elements.copyStatus.textContent = '⚠️ Clipboard security risk';
                UIManager.elements.copyStatus.className = 'text-sm text-yellow-600';
            }, 3000);
            
        } catch (error) {
            UIManager.elements.copyStatus.textContent = '✗ Copy failed';
            UIManager.elements.copyStatus.className = 'text-sm text-red-600';
        }
    }
}

/**
 * Memory Manager Class
 * Implements Function: ClearSensitiveData (EncryptionFunctions.fun line 73)
 * Follows Requirement: REQ_SEC_001 (EncryptionRequirements.req line 133)
 * Per ThreatModel.md T-INFO-02 mitigation
 */
class MemoryManager {
    /**
     * Clear sensitive data from memory
     * Implements Function: ClearSensitiveData (EncryptionFunctions.fun line 73)
     */
    static clearSensitiveData() {
        // Clear application state
        AppState.currentKey = null;
        AppState.lastEncryptedData = null;
        
        // Force garbage collection hint (browser dependent)
        if (window.gc) {
            window.gc();
        }
    }
}

/**
 * Main Encryption Controller
 * Implements Function: ProcessUserInput (EncryptionFunctions.fun line 91)
 * Orchestrates the complete encryption workflow
 * Follows Requirements: REQ_FUNC_002, REQ_PERF_001 (EncryptionRequirements.req)
 */
class EncryptionController {
    /**
     * Process user input through complete encryption workflow
     * Implements Function: ProcessUserInput (EncryptionFunctions.fun line 91)
     * Follows Requirement: REQ_PERF_001 (EncryptionRequirements.req line 115) - 2 second limit
     */
    static async processEncryption() {
        if (AppState.isProcessing) {
            return; // Prevent concurrent operations
        }
        
        try {
            AppState.isProcessing = true;
            UIManager.showProcessing();
            
            // Performance tracking per REQ_PERF_001
            const startTime = performance.now();
            
            // Step 1: Validate input (Function: ValidateTextInput)
            const input = UIManager.elements.inputText.value;
            const validation = InputValidator.validate(input);
            
            if (!validation.isValid) {
                throw new Error(validation.errors[0]);
            }
            
            // Step 2: Generate cryptographic key (Function: GenerateCryptographicKey)
            const key = await CryptographicEngine.generateKey();
            AppState.currentKey = key;
            
            // Step 3: Generate IV (Function: EncryptText)
            const iv = CryptographicEngine.generateIV();
            
            // Step 4: Encrypt text (Function: EncryptText)
            const encryptedData = await CryptographicEngine.encryptText(validation.sanitized, key, iv);
            AppState.lastEncryptedData = encryptedData;
            
            // Step 5: Format output (Function: FormatEncryptedOutput)
            const formattedOutput = OutputFormatter.formatOutput(iv, encryptedData);
            
            // Step 6: Display result (Function: DisplayEncryptedResult)
            UIManager.displayResult(formattedOutput);
            
            // Performance check per REQ_PERF_001
            const endTime = performance.now();
            const processingTime = endTime - startTime;
            
            if (processingTime > 2000) {
                console.warn(`Encryption took ${processingTime}ms - exceeds 2s requirement`);
            }
            
            // Step 7: Clear sensitive data (Function: ClearSensitiveData)
            // Keys are automatically cleared as they're not extractable
            // IV and intermediate data will be garbage collected
            
        } catch (error) {
            // Step 8: Handle errors (Function: HandleEncryptionError)
            console.error('Encryption error:', error);
            UIManager.showError('Encryption failed. Please try again.');
        } finally {
            AppState.isProcessing = false;
            UIManager.hideProcessing();
            
            // Clear sensitive references
            setTimeout(() => {
                MemoryManager.clearSensitiveData();
            }, 100);
        }
    }
}

/**
 * Application Initialization
 * Implements Function: InitializeUserInterface (EncryptionFunctions.fun line 82)
 * Entry point that sets up the complete application
 */
document.addEventListener('DOMContentLoaded', () => {
    // Check Web Crypto API support per CryptoDecision.md browser compatibility
    if (!window.crypto || !window.crypto.subtle) {
        alert('Your browser does not support the Web Crypto API. Please use a modern browser.');
        return;
    }
    
    // Initialize application
    UIManager.initialize();
    
    console.log('Encryption Web App initialized');
    console.log('Implementation follows Sylang documentation:');
    console.log('- EncryptionWebApp.fml (Features)');
    console.log('- EncryptionFunctions.fun (Functions)');
    console.log('- EncryptionRequirements.req (Requirements)');
    console.log('- CryptoDecision.md (Crypto specifications)');
    console.log('- InputValidation.md (Input validation)');
    console.log('- ThreatModel.md (Security mitigations)');
});

// Security: Prevent console access to sensitive functions in production
if (typeof window !== 'undefined') {
    // Make classes available for debugging in development only
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        window.EncryptionApp = {
            InputValidator,
            CryptographicEngine,
            OutputFormatter,
            UIManager,
            ClipboardManager,
            MemoryManager,
            EncryptionController
        };
    }
}
