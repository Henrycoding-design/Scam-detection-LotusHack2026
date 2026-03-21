import { useEffect, useState } from 'react';
import { connectToBackground, getActiveTabId } from './chrome';
import type { ElementData } from './types';
import StatsRow from './components/StatsRow';
import ElementCard from './components/ElementCard';
import { getStatusColor } from './utils';

type FilterType = 'all' | 'unsafe' | 'safe' | 'pending';

export default function App() {
  const [elements, setElements] = useState<Map<string, ElementData>>(new Map<string, ElementData>());
  const [tabId, setTabId] = useState<number | null>(null);
  const [filter, setFilter] = useState<FilterType>('all');
  const [selectedElement, setSelectedElement] = useState<ElementData | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initialize connection and fetch initial data
  useEffect(() => {
    let connection: ReturnType<typeof connectToBackground> | null = null;

    const init = async () => {
      try {
        const activeTabId = await getActiveTabId();
        setTabId(activeTabId);
        
        connection = connectToBackground(activeTabId);
        setConnected(true);
        
        connection.onMessage((message) => {
          if (message.type === 'ELEMENT_UPDATE') {
            setElements(prev => {
              const next = new Map(prev);
              next.set(message.elementId, message.data);
              return next;
            });
          }
        });
        
        // Request initial full sync
        chrome.runtime.sendMessage(
          { type: 'GET_TAB_DATA', tabId: activeTabId },
          (response: { elements?: ElementData[] }) => {
            if (response.elements) {
              const map = new Map<string, ElementData>();
              response.elements.forEach(el => map.set(el.elementId, el));
              setElements(map);
            }
          }
        );
      } catch (err) {
        setError('Failed to connect to ScamShield background script. Is the extension loaded?');
        console.error(err);
      }
    };
    
    init();
    return () => connection?.disconnect();
  }, []);

  // Compute stats (memoized on elements map reference)
  const stats = (() => {
    let safe = 0, unsafe = 0, pending = 0, errors = 0;
    for (const el of elements.values()) {
      switch (el.status) {
        case 'safe': safe++; break;
        case 'unsafe': unsafe++; break;
        case 'pending': pending++; break;
        case 'error': errors++; break;
      }
    }
    return { total: elements.size, safe, unsafe, pending, errors };
  })();

  // Filter elements
  const filteredElements: ElementData[] = [];
  for (const el of elements.values()) {
    if (filter === 'all' || el.status === filter) {
      filteredElements.push(el);
    }
  }

  // Sort by risk score descending, then timestamp
  filteredElements.sort((a, b) => {
    if (b.riskScore !== a.riskScore) return b.riskScore - a.riskScore;
    return b.timestamp - a.timestamp;
  });

  if (error) {
    return (
      <div className="p-4 bg-gray-900 text-white min-h-screen">
        <div className="text-red-400">{error}</div>
      </div>
    );
  }

  return (
    <div className="p-4 bg-gray-900 text-white min-h-screen">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-red-500">ScamShield Dashboard</h1>
          <div className="flex items-center gap-2 mt-1">
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}></div>
            <span className="text-sm text-gray-400">
              {connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
        <div className="text-right">
          <div className="text-xs text-gray-500">Current Tab</div>
          <div className="text-sm text-gray-300 truncate max-w-xs">
            {tabId !== null ? `Tab ID: ${tabId}` : 'Loading...'}
          </div>
        </div>
      </div>

      {/* Stats */}
      <StatsRow stats={stats} />

      {/* Filters */}
      <div className="flex gap-2 mb-4 flex-wrap">
        {(['all', 'unsafe', 'safe', 'pending'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded text-sm ${
              filter === f
                ? 'bg-red-600 text-white'
                : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
            {f !== 'all' && ` (${stats[f]})`}
          </button>
        ))}
      </div>

      {/* Element List */}
      <div className="space-y-3">
        {filteredElements.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            {filter === 'all' 
              ? 'No threats detected yet. Scanning links, downloads, text content, and crypto addresses in real-time.'
              : `No ${filter} elements found.`}
          </div>
        ) : (
          filteredElements.map(el => (
            <ElementCard
              key={el.elementId}
              element={el}
              onClick={() => setSelectedElement(el)}
            />
          ))
        )}
      </div>

      {/* Detail Modal */}
      {selectedElement && (
        <div
          className="fixed inset-0 bg-black bg-opacity-80 flex items-center justify-center z-50 p-4"
          onClick={() => setSelectedElement(null)}
        >
          <div
            className="bg-gray-800 rounded-lg max-w-2xl w-full p-6"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex justify-between items-start mb-4">
              <h2 className="text-xl font-bold text-red-500">
                Element Details
              </h2>
              <button
                onClick={() => setSelectedElement(null)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <div className="text-sm text-gray-500">Type</div>
                <div className="font-mono bg-gray-900 p-2 rounded inline-block">
                  {selectedElement.type}
                </div>
              </div>
              
              {selectedElement.url && (
                <div>
                  <div className="text-sm text-gray-500">URL</div>
                  <div className="flex items-start gap-2">
                    <code className="font-mono bg-gray-900 p-2 rounded text-blue-400 break-all flex-1">
                      {selectedElement.url}
                    </code>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(selectedElement.url || '');
                      }}
                      className="px-2 py-1 bg-gray-700 rounded hover:bg-gray-600 text-sm"
                    >
                      Copy
                    </button>
                  </div>
                </div>
              )}
              
              {selectedElement.text && (
                <div>
                  <div className="text-sm text-gray-500">Text</div>
                  <div className="bg-gray-900 p-2 rounded text-gray-300 italic">
                    "{selectedElement.text}"
                  </div>
                </div>
              )}
              
              <div className="flex gap-4">
                <div>
                  <div className="text-sm text-gray-500">Status</div>
                  <div className={`font-bold ${getStatusColor(selectedElement.status)}`}>
                    {selectedElement.status.toUpperCase()}
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-500">Risk Score</div>
                  <div className={`font-bold ${selectedElement.riskScore >= 70 ? 'text-red-400' : selectedElement.riskScore > 0 ? 'text-yellow-400' : 'text-green-400'}`}>
                    {selectedElement.riskScore}/100
                  </div>
                </div>
                <div>
                  <div className="text-sm text-gray-500">Source</div>
                  <div className="font-mono text-gray-400">
                    {selectedElement.source || 'None'}
                  </div>
                </div>
              </div>
              
              {selectedElement.details && (
                <div>
                  <div className="text-sm text-gray-500">Detection Details</div>
                  <div className="bg-gray-900 p-2 rounded text-gray-300 text-sm">
                    {selectedElement.details}
                  </div>
                </div>
              )}
              
              {selectedElement.matchedPhrases && selectedElement.matchedPhrases.length > 0 && (
                <div>
                  <div className="text-sm text-gray-500">Matched Patterns</div>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedElement.matchedPhrases.map((p, i) => (
                      <span key={i} className="text-xs bg-red-900/50 text-red-300 px-2 py-1 rounded">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              
              {selectedElement.contextSnippet && (
                <div>
                  <div className="text-sm text-gray-500">Context</div>
                  <div className="bg-gray-900 p-2 rounded text-gray-400 text-xs font-mono break-all">
                    {selectedElement.contextSnippet}
                  </div>
                </div>
              )}
              
              <div>
                <div className="text-sm text-gray-500">Short Explanation</div>
                <div className="bg-gray-900 p-3 rounded text-yellow-300">
                  {selectedElement.shortExplanation || 'No explanation available.'}
                </div>
              </div>
              
              <div>
                <div className="text-sm text-gray-500">Detailed Explanation</div>
                <div className="bg-gray-900 p-3 rounded text-gray-200 leading-relaxed">
                  {selectedElement.longExplanation || 'No detailed explanation available.'}
                </div>
              </div>
              
              <div className="text-xs text-gray-500 pt-2 border-t border-gray-700">
                Detected: {new Date(selectedElement.timestamp).toLocaleString()}
              </div>
              
               {selectedElement.status === 'unsafe' && selectedElement.url && (
                 <div className="flex gap-3 pt-2">
                   <button
                      onClick={() => {
                        const el = selectedElement!;
                        chrome.runtime.sendMessage({
                          type: 'RESTORE_ELEMENT',
                          elementId: el.elementId,
                          tabId: tabId
                        });
                       if (el.url) {
                         chrome.tabs.create({ url: el.url });
                       }
                       setSelectedElement(null);
                     }}
                     className="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded"
                   >
                     Visit Anyway (Risky)
                   </button>
                   <button
                     onClick={() => setSelectedElement(null)}
                     className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded"
                   >
                     Close
                   </button>
                 </div>
               )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
