export type ExternalLaunchTarget = 'encrypt' | 'timecapsule'

export interface ExternalLaunchAction {
  target: ExternalLaunchTarget
  paths: string[]
  source?: 'windows-context-menu' | 'cli'
}

export interface PendingExternalLaunchAction extends ExternalLaunchAction {
  nonce: number
}
