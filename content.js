// content.js - IMPROVED VERSION with comprehensive detection

(function() {
  console.log('🔒 Privacy Analyzer: Starting comprehensive analysis...');
  
  const results = {
    url: window.location.href,
    timestamp: new Date().toISOString(),
    thirdPartyDomains: [],
    thirdPartyResources: {
      scripts: [],
      images: [],
      stylesheets: [],
      iframes: [],
      fonts: []
    },
    evalPatterns: [],
    fingerprintingAPIs: [],
    canvasFingerprinting: false,
    fontFingerprinting: false,
    webglFingerprinting: false,
    localStorageAccess: false,
    cookieCount: 0
  };
  
  // Extract root domain (handle subdomains properly)
  function extractRootDomain(hostname) {
    const parts = hostname.split('.');
    // Handle cases like: www.example.com, api.example.com, example.com
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return hostname;
  }
  
  const mainDomain = extractRootDomain(window.location.hostname);
  console.log('Main domain:', mainDomain);
  
  // 1. DETECT ALL THIRD-PARTY RESOURCES (improved)
  function detectThirdPartyResources() {
    const thirdPartySet = new Set();
    
    // Check scripts
    document.querySelectorAll('script[src]').forEach(script => {
      try {
        const url = new URL(script.src, window.location.href);
        const scriptDomain = extractRootDomain(url.hostname);
        
        if (scriptDomain !== mainDomain) {
          thirdPartySet.add(scriptDomain);
          results.thirdPartyResources.scripts.push(url.hostname);
        }
      } catch (e) {
        console.warn('Invalid script URL:', script.src);
      }
    });
    
    // Check images
    document.querySelectorAll('img[src], img[data-src]').forEach(img => {
      try {
        const src = img.src || img.getAttribute('data-src');
        if (src && src.startsWith('http')) {
          const url = new URL(src);
          const imgDomain = extractRootDomain(url.hostname);
          
          if (imgDomain !== mainDomain) {
            thirdPartySet.add(imgDomain);
            results.thirdPartyResources.images.push(url.hostname);
          }
        }
      } catch (e) {}
    });
    
    // Check stylesheets
    document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
      try {
        const url = new URL(link.href);
        const cssDomain = extractRootDomain(url.hostname);
        
        if (cssDomain !== mainDomain) {
          thirdPartySet.add(cssDomain);
          results.thirdPartyResources.stylesheets.push(url.hostname);
        }
      } catch (e) {}
    });
    
    // Check iframes
    document.querySelectorAll('iframe[src]').forEach(iframe => {
      try {
        const url = new URL(iframe.src);
        const iframeDomain = extractRootDomain(url.hostname);
        
        if (iframeDomain !== mainDomain) {
          thirdPartySet.add(iframeDomain);
          results.thirdPartyResources.iframes.push(url.hostname);
        }
      } catch (e) {}
    });
    
    // Check fonts
    document.querySelectorAll('link[rel*="font"], link[href*="fonts.googleapis"]').forEach(link => {
      try {
        const url = new URL(link.href);
        const fontDomain = extractRootDomain(url.hostname);
        
        if (fontDomain !== mainDomain) {
          thirdPartySet.add(fontDomain);
          results.thirdPartyResources.fonts.push(url.hostname);
        }
      } catch (e) {}
    });
    
    results.thirdPartyDomains = Array.from(thirdPartySet);
    console.log('Third-party domains found:', results.thirdPartyDomains.length);
  }
  
  // 2. DETECT EVAL AND DANGEROUS PATTERNS (improved)
  function detectEvalPatterns() {
    const evalPatterns = [];
    const scripts = document.querySelectorAll('script');
    
    scripts.forEach((script, index) => {
      const content = script.textContent;
      if (!content) return;
      
      // Check for eval()
      if (content.match(/\beval\s*\(/)) {
        evalPatterns.push({
          type: 'eval() usage',
          location: script.src || 'Inline script #' + index,
          preview: content.substring(0, 80).replace(/\s+/g, ' ')
        });
      }
      
      // Check for Function constructor
      if (content.match(/new\s+Function\s*\(/i)) {
        evalPatterns.push({
          type: 'Function constructor',
          location: script.src || 'Inline script #' + index
        });
      }
      
      // Check for setTimeout/setInterval with strings
      if (content.match(/setTimeout\s*\(\s*['"`]/) || content.match(/setInterval\s*\(\s*['"`]/)) {
        evalPatterns.push({
          type: 'setTimeout/setInterval with string',
          location: script.src || 'Inline script #' + index
        });
      }
      
      // Check for document.write
      if (content.match(/document\.write\s*\(/)) {
        evalPatterns.push({
          type: 'document.write() usage',
          location: script.src || 'Inline script #' + index
        });
      }
    });
    
    results.evalPatterns = evalPatterns;
    console.log('Eval patterns found:', evalPatterns.length);
  }
  
  // 3. DETECT FINGERPRINTING APIs (much improved)
  function detectFingerprintingAPIs() {
    const fingerprintingAPIs = new Set();
    const scripts = document.querySelectorAll('script');
    
    // Comprehensive list of fingerprinting APIs
    const fingerprintingPatterns = {
      navigator: [
        'navigator.userAgent',
        'navigator.platform',
        'navigator.language',
        'navigator.languages',
        'navigator.hardwareConcurrency',
        'navigator.deviceMemory',
        'navigator.maxTouchPoints',
        'navigator.vendor',
        'navigator.appVersion',
        'navigator.doNotTrack',
        'navigator.plugins',
        'navigator.mimeTypes'
      ],
      screen: [
        'screen.width',
        'screen.height',
        'screen.availWidth',
        'screen.availHeight',
        'screen.colorDepth',
        'screen.pixelDepth',
        'window.screen',
        'window.innerWidth',
        'window.innerHeight',
        'window.outerWidth',
        'window.outerHeight'
      ],
      timezone: [
        'Intl.DateTimeFormat',
        'getTimezoneOffset',
        'toTimeString'
      ],
      battery: [
        'navigator.getBattery',
        'BatteryManager'
      ],
      webgl: [
        'WebGLRenderingContext',
        'getParameter',
        'RENDERER',
        'VENDOR'
      ]
    };
    
    // Check all scripts for these patterns
    scripts.forEach(script => {
      const content = script.textContent.toLowerCase();
      
      Object.values(fingerprintingPatterns).flat().forEach(api => {
        if (content.includes(api.toLowerCase())) {
          fingerprintingAPIs.add(api);
        }
      });
    });
    
    results.fingerprintingAPIs = Array.from(fingerprintingAPIs);
    console.log('Fingerprinting APIs found:', fingerprintingAPIs.size);
  }
  
  // 4. DETECT CANVAS FINGERPRINTING (runtime detection)
  function detectCanvasFingerprinting() {
    let canvasDetected = false;
    
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const originalToBlob = HTMLCanvasElement.prototype.toBlob;
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    
    HTMLCanvasElement.prototype.toDataURL = function(...args) {
      console.log('🎨 Canvas toDataURL called - possible fingerprinting');
      canvasDetected = true;
      results.canvasFingerprinting = true;
      return originalToDataURL.apply(this, args);
    };
    
    HTMLCanvasElement.prototype.toBlob = function(...args) {
      console.log('🎨 Canvas toBlob called - possible fingerprinting');
      canvasDetected = true;
      results.canvasFingerprinting = true;
      return originalToBlob.apply(this, args);
    };
    
    CanvasRenderingContext2D.prototype.getImageData = function(...args) {
      console.log('🎨 Canvas getImageData called - possible fingerprinting');
      canvasDetected = true;
      results.canvasFingerprinting = true;
      return originalGetImageData.apply(this, args);
    };
  }
  
  // 5. DETECT WEBGL FINGERPRINTING
  function detectWebGLFingerprinting() {
    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
    
    WebGLRenderingContext.prototype.getParameter = function(param) {
      // Check if getting RENDERER or VENDOR (common for fingerprinting)
      if (param === 0x1F00 || param === 0x1F01 || param === 0x9245 || param === 0x9246) {
        console.log('🎮 WebGL fingerprinting detected');
        results.webglFingerprinting = true;
      }
      return originalGetParameter.apply(this, arguments);
    };
  }
  
  // 6. DETECT FONT FINGERPRINTING
  function detectFontFingerprinting() {
    const scripts = document.querySelectorAll('script');
    
    scripts.forEach(script => {
      const content = script.textContent;
      
      // Check for font detection patterns
      if (content.includes('measureText') || 
          content.includes('offsetWidth') && content.includes('font') ||
          content.match(/fonts?.*detect/i)) {
        results.fontFingerprinting = true;
        console.log('🔤 Font fingerprinting detected');
      }
    });
  }
  
  // 7. CHECK COOKIES
  function checkCookies() {
    results.cookieCount = document.cookie.split(';').filter(c => c.trim()).length;
    console.log('Cookies found:', results.cookieCount);
  }
  
  // 8. CHECK LOCALSTORAGE ACCESS
  function checkLocalStorage() {
    try {
      const originalSetItem = Storage.prototype.setItem;
      Storage.prototype.setItem = function(...args) {
        results.localStorageAccess = true;
        return originalSetItem.apply(this, args);
      };
    } catch (e) {
      console.log('LocalStorage check failed:', e);
    }
  }
  
  // Run all detection methods
  function runAnalysis() {
    detectThirdPartyResources();
    detectEvalPatterns();
    detectFingerprintingAPIs();
    detectCanvasFingerprinting();
    detectWebGLFingerprinting();
    detectFontFingerprinting();
    checkCookies();
    checkLocalStorage();
    
    console.log('📊 Analysis Results:', results);
    
    // Send results to background script
    chrome.runtime.sendMessage({
      type: 'ANALYSIS_COMPLETE',
      data: results
    }, response => {
      if (chrome.runtime.lastError) {
        console.error('Error sending message:', chrome.runtime.lastError);
      } else {
        console.log('✅ Results sent to background successfully');
      }
    });
  }
  
  // Run analysis after page fully loads
  if (document.readyState === 'complete') {
    runAnalysis();
  } else {
    window.addEventListener('load', () => {
      // Wait a bit more for dynamic content
      setTimeout(runAnalysis, 2000);
    });
  }
  
})();