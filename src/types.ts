// Element data structure shared between background and dashboard
export type ElementType =
  | 'link'
  | 'button'
  | 'download'
  | 'fileInput'
  | 'iframe'
  | 'video'
  | 'audio'
  | 'embed'
  | 'object'
  | 'form'
  | 'clickable';

export type ElementStatus = 'pending' | 'safe' | 'unsafe' | 'error';

export type ScanSource = 'gsb' | 'vt' | 'ai' | 'none' | 'manual' | null;

export interface ElementData {
  elementId: string;
  tabId: number;
  type: ElementType;
  url?: string;
  text: string;
  status: ElementStatus;
  riskScore: number;
  shortExplanation: string;
  longExplanation: string;
  source: ScanSource;
  details: string;
  timestamp: number;
  chromeFrameId?: number;
  vtAnalysisId?: string;
  vtStatus?: 'submitted' | 'completed' | 'error';
}

export interface PageContext {
  url: string;
  title: string;
  visibleText: string;
  timestamp: number;
  elements: Array<{
    elementId: string;
    type: ElementType;
    url?: string;
    text: string;
    isVisible: boolean;
    hasLoginKeyword?: boolean;
  }>;
}
