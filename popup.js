// popup.js - IMPROVED VERSION with better result display

document.addEventListener('DOMContentLoaded', () => {
  loadAnalysis();
  setupThemeToggle();
  setupExport();
  setupRefresh();
});

function loadAnalysis() {
  const loading = document.getElementById('loading');
  const results = document.getElementById('results');
  const error = document.getElementById('error');
  
  chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' }, (response) => {
    loading.classList.add('hidden');
    
    if (response && response.data) {
      results.classList.remove('hidden');
      displayResults(response.data);
      
      // Show summary stats
      displaySummary(response.data);
    } else {
      error.classList.remove('hidden');
    }
  });
}

function displaySummary(data) {
  const totalIssues = 
    data.thirdPartyDomains.length +
    data.evalPatterns.length +
    data.fingerprintingAPIs.length +
    (data.canvasFingerprinting ? 1 : 0) +
    (data.webglFingerprinting ? 1 : 0) +
    (data.fontFingerprinting ? 1 : 0);
  
  // Calculate privacy score (0-100, higher is better)
  let score = 100;
  score -= Math.min(data.thirdPartyDomains.length * 2, 40); // Max -40
  score -= Math.min(data.evalPatterns.length * 5, 20); // Max -20
  score -= Math.min(data.fingerprintingAPIs.length * 3, 30); // Max -30
  score -= data.canvasFingerprinting ? 10 : 0;
  score -= data.webglFingerprinting ? 5 : 0;
  score -= data.fontFingerprinting ? 5 : 0;
  score = Math.max(score, 0);
  
  const summaryDiv = document.getElementById('summary');
  if (summaryDiv) {
    let scoreColor = score >= 70 ? '#4CAF50' : score >= 40 ? '#ff9800' : '#d32f2f';
    let scoreLabel = score >= 70 ? 'Good' : score >= 40 ? 'Fair' : 'Poor';
    
    summaryDiv.innerHTML = `
      <div class="privacy-score" style="color: ${scoreColor}">
        <div class="score-number">${score}</div>
        <div class="score-label">Privacy Score (${scoreLabel})</div>
      </div>
      <div class="issue-count">
        <strong>${totalIssues}</strong> total issues detected
      </div>
    `;
  }
}

function displayResults(data) {
  // Display third-party trackers with breakdown
  const trackersDiv = document.getElementById('trackers');
  if (data.thirdPartyDomains.length > 0) {
    const breakdown = {
      scripts: data.thirdPartyResources?.scripts?.length || 0,
      images: data.thirdPartyResources?.images?.length || 0,
      stylesheets: data.thirdPartyResources?.stylesheets?.length || 0,
      iframes: data.thirdPartyResources?.iframes?.length || 0,
      fonts: data.thirdPartyResources?.fonts?.length || 0
    };
    
    trackersDiv.innerHTML = `
      <p class="count">🔴 ${data.thirdPartyDomains.length} third-party domains</p>
      <div class="breakdown">
        ${breakdown.scripts > 0 ? `<span>📜 ${breakdown.scripts} scripts</span>` : ''}
        ${breakdown.images > 0 ? `<span>🖼️ ${breakdown.images} images</span>` : ''}
        ${breakdown.stylesheets > 0 ? `<span>🎨 ${breakdown.stylesheets} stylesheets</span>` : ''}
        ${breakdown.iframes > 0 ? `<span>🖼️ ${breakdown.iframes} iframes</span>` : ''}
        ${breakdown.fonts > 0 ? `<span>🔤 ${breakdown.fonts} fonts</span>` : ''}
      </div>
      <details>
        <summary>View all domains (${data.thirdPartyDomains.length})</summary>
        <ul>
          ${data.thirdPartyDomains.slice(0, 20).map(domain => `
            <li>${domain}${isKnownTracker(domain) ? ' <span class="badge">Known Tracker</span>' : ''}</li>
          `).join('')}
          ${data.thirdPartyDomains.length > 20 ? `<li>... and ${data.thirdPartyDomains.length - 20} more</li>` : ''}
        </ul>
      </details>
    `;
  } else {
    trackersDiv.innerHTML = '<p class="safe">✅ No third-party trackers detected</p>';
  }
  
  // Display eval patterns with details
  const evalDiv = document.getElementById('eval');
  if (data.evalPatterns.length > 0) {
    evalDiv.innerHTML = `
      <p class="count warning">⚠️ ${data.evalPatterns.length} dangerous patterns found</p>
      <ul>
        ${data.evalPatterns.map(p => `
          <li>
            <strong>${p.type}</strong>
            ${p.location ? `<br><small>Location: ${p.location}</small>` : ''}
          </li>
        `).join('')}
      </ul>
    `;
  } else {
    evalDiv.innerHTML = '<p class="safe">✅ No dangerous code patterns detected</p>';
  }
  
  // Display fingerprinting APIs grouped by category
  const fingerprintingDiv = document.getElementById('fingerprinting');
  if (data.fingerprintingAPIs.length > 0) {
    const categories = categorizeAPIs(data.fingerprintingAPIs);
    
    fingerprintingDiv.innerHTML = `
      <p class="count warning">👁️ ${data.fingerprintingAPIs.length} fingerprinting APIs accessed</p>
      ${Object.entries(categories).map(([category, apis]) => `
        <details>
          <summary><strong>${category}</strong> (${apis.length})</summary>
          <ul>
            ${apis.map(api => `<li><code>${api}</code></li>`).join('')}
          </ul>
        </details>
      `).join('')}
    `;
  } else {
    fingerprintingDiv.innerHTML = '<p class="safe">✅ No fingerprinting APIs detected</p>';
  }
  
  // Display advanced fingerprinting techniques
  const advancedDiv = document.getElementById('advanced');
  const advancedTechniques = [];
  
  if (data.canvasFingerprinting) {
    advancedTechniques.push('🎨 Canvas Fingerprinting');
  }
  if (data.webglFingerprinting) {
    advancedTechniques.push('🎮 WebGL Fingerprinting');
  }
  if (data.fontFingerprinting) {
    advancedTechniques.push('🔤 Font Fingerprinting');
  }
  
  if (advancedTechniques.length > 0) {
    advancedDiv.innerHTML = `
      <p class="count warning">⚠️ ${advancedTechniques.length} advanced techniques detected</p>
      <ul>
        ${advancedTechniques.map(tech => `<li>${tech}</li>`).join('')}
      </ul>
    `;
  } else {
    advancedDiv.innerHTML = '<p class="safe">✅ No advanced fingerprinting detected</p>';
  }
  
  // Display additional info
  const additionalDiv = document.getElementById('additional');
  additionalDiv.innerHTML = `
    <p>🍪 <strong>${data.cookieCount || 0}</strong> cookies found</p>
    <p>💾 Local storage: ${data.localStorageAccess ? '⚠️ Accessed' : '✅ Not accessed'}</p>
    <p>🕐 Analysis time: ${new Date(data.timestamp).toLocaleString()}</p>
  `;
}

function categorizeAPIs(apis) {
  const categories = {
    'Navigator Info': [],
    'Screen/Display': [],
    'Hardware': [],
    'Time/Locale': [],
    'Other': []
  };
  
  apis.forEach(api => {
    if (api.includes('navigator.user') || api.includes('navigator.platform') || 
        api.includes('navigator.vendor') || api.includes('navigator.app')) {
      categories['Navigator Info'].push(api);
    } else if (api.includes('screen') || api.includes('Width') || api.includes('Height')) {
      categories['Screen/Display'].push(api);
    } else if (api.includes('hardware') || api.includes('memory') || api.includes('Touch')) {
      categories['Hardware'].push(api);
    } else if (api.includes('Time') || api.includes('timezone') || api.includes('Intl')) {
      categories['Time/Locale'].push(api);
    } else {
      categories['Other'].push(api);
    }
  });
  
  // Remove empty categories
  return Object.fromEntries(
    Object.entries(categories).filter(([_, apis]) => apis.length > 0)
  );
}

function isKnownTracker(domain) {
  const knownTrackers = [
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'facebook.com', 'facebook.net', 'fbcdn.net',
    'twitter.com', 'twimg.com',
    'amazon-adsystem.com', 'googlesyndication.com',
    'hotjar.com', 'mouseflow.com', 'crazyegg.com',
    'mixpanel.com', 'segment.com', 'amplitude.com'
  ];
  
  return knownTrackers.some(tracker => domain.includes(tracker));
}

function setupThemeToggle() {
  const toggle = document.getElementById('themeToggle');
  const currentTheme = localStorage.getItem('theme') || 'light';
  
  document.body.classList.add(currentTheme + '-theme');
  toggle.textContent = currentTheme === 'light' ? '🌙' : '☀️';
  
  toggle.addEventListener('click', () => {
    const isDark = document.body.classList.contains('dark-theme');
    
    if (isDark) {
      document.body.classList.remove('dark-theme');
      document.body.classList.add('light-theme');
      toggle.textContent = '🌙';
      localStorage.setItem('theme', 'light');
    } else {
      document.body.classList.remove('light-theme');
      document.body.classList.add('dark-theme');
      toggle.textContent = '☀️';
      localStorage.setItem('theme', 'dark');
    }
  });
}

function setupExport() {
  const exportBtn = document.getElementById('exportBtn');
  
  exportBtn.addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' }, (response) => {
      if (response && response.data) {
        const dataStr = JSON.stringify(response.data, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        
        const hostname = new URL(response.data.url).hostname;
        link.download = `privacy-report-${hostname}-${Date.now()}.json`;
        link.click();
        
        URL.revokeObjectURL(url);
      }
    });
  });
}

function setupRefresh() {
  const refreshBtn = document.getElementById('refreshBtn');
  
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      // Reload the current tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        chrome.tabs.reload(tabs[0].id);
        window.close();
      });
    });
  }
}