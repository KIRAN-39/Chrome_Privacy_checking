// background.js - Stores analysis data

let analysisData = {};

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYSIS_COMPLETE') {
    const tabId = sender.tab.id;
    analysisData[tabId] = message.data;
    console.log('Background: Stored analysis for tab', tabId);
    sendResponse({ success: true });
  }
  
  // Popup requests data
  if (message.type === 'GET_ANALYSIS') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const currentTab = tabs[0];
      const data = analysisData[currentTab.id] || null;
      sendResponse({ data: data });
    });
    return true; // Keep channel open for async response
  }
  
  return true;
});

// Clean up when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete analysisData[tabId];
});