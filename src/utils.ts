// Shared utility functions for the dashboard

export function getStatusColor(status: string): string {
  switch (status) {
    case 'safe': return 'text-green-400';
    case 'unsafe': return 'text-red-400';
    case 'pending': return 'text-yellow-400';
    case 'error': return 'text-gray-400';
    default: return 'text-gray-400';
  }
}

export function getRiskColor(score: number): string {
  if (score >= 80) return 'bg-red-600';
  if (score >= 50) return 'bg-yellow-500';
  return 'bg-green-500';
}

export function getTypeIcon(type: string): string {
  switch (type) {
    case 'link': return '🔗';
    case 'button': return '🔘';
    case 'download': return '⬇️';
    case 'fileInput': return '📁';
    case 'iframe': return '🖼️';
    case 'video': return '🎬';
    case 'audio': return '🔊';
    case 'embed': return '📦';
    case 'object': return '📦';
    case 'form': return '📝';
    case 'submit': return '📨';
    case 'clickable': return '👆';
    case 'textThreat': return '⚠️';
    case 'cryptoAddress': return '💰';
    case 'clipboardHijack': return '📋';
    case 'phishingForm': return '🎣';
    default: return '❓';
  }
}
