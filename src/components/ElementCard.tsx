import type { ElementData, ElementType } from '../types';
import { getTypeIcon, getStatusColor, getRiskColor } from '../utils';

interface ElementCardProps {
  key?: string | number;
  element: ElementData;
  onClick: () => void;
}

const isTextType = (t: ElementType) => ['textThreat', 'cryptoAddress', 'clipboardHijack', 'phishingForm'].includes(t);

export default function ElementCard({ element, onClick }: ElementCardProps) {
  const statusLabel = element.status === 'unsafe' 
    ? `Risk: ${element.riskScore}/100`
    : element.status.toUpperCase();

  return (
    <div
      className={`p-3 rounded-lg cursor-pointer transition-all ${
        element.status === 'unsafe' 
          ? 'bg-red-900/30 border border-red-700 hover:bg-red-900/50' 
          : element.status === 'pending'
          ? 'bg-yellow-900/30 border border-yellow-700 hover:bg-yellow-900/50'
          : 'bg-gray-800 hover:bg-gray-750'
      }`}
      onClick={onClick}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <span className="text-xl flex-shrink-0">{getTypeIcon(element.type)}</span>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-xs font-mono px-2 py-0.5 rounded bg-gray-700 ${getStatusColor(element.status)}`}>
                {element.type.toUpperCase()}
              </span>
              <span className={`text-xs font-bold ${getStatusColor(element.status)}`}>
                {statusLabel}
              </span>
            </div>
            
            {element.url && (
              <div className="font-mono text-blue-400 text-sm truncate mb-1" title={element.url}>
                {element.url}
              </div>
            )}
            
            {element.text && (
              <div className="text-gray-300 text-sm truncate" title={element.text}>
                "{element.text}"
              </div>
            )}
            
            {/* Matched phrases for text threats */}
            {isTextType(element.type) && element.matchedPhrases && element.matchedPhrases.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {element.matchedPhrases.slice(0, 3).map((p, i) => (
                  <span key={i} className="text-xs bg-red-900/50 text-red-300 px-1.5 py-0.5 rounded">
                    {p.length > 40 ? p.slice(0, 37) + '...' : p}
                  </span>
                ))}
                {element.matchedPhrases.length > 3 && (
                  <span className="text-xs text-gray-500">+{element.matchedPhrases.length - 3} more</span>
                )}
              </div>
            )}

            {/* Short explanation if unsafe */}
            {element.status === 'unsafe' && element.shortExplanation && !isTextType(element.type) && (
              <div className="text-yellow-300 text-xs mt-2 italic">
                {element.shortExplanation}
              </div>
            )}
            
            {/* Pending indicator */}
            {element.status === 'pending' && (
              <div className="text-yellow-400 text-xs mt-1">
                Scanning...
              </div>
            )}
          </div>
        </div>
        
        {/* Risk bar for unsafe elements */}
        {element.status === 'unsafe' && (
          <div className="flex flex-col items-end gap-1">
            <div className="text-right text-xs text-gray-400">
              {element.source?.toUpperCase()}
            </div>
            <div className="w-16 h-2 bg-gray-700 rounded overflow-hidden">
              <div
                className={`h-full ${getRiskColor(element.riskScore)}`}
                style={{ width: `${element.riskScore}%` }}
              ></div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
