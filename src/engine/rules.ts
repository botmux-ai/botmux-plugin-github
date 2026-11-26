import type { PullRequestInfo, RepoRule, TriggerKind } from '../types.ts';
import { MAX_IPC_TEXT_BYTES } from '../types.ts';
import {
  fitUntrustedPrMetadataXml,
  sanitizeSafeHttpUrl,
  sanitizeUntrustedText,
  truncateUtf8Bytes,
} from '../security/sanitize.ts';

export interface RuleMatchResult {
  matched: boolean;
  reason?: string;
}

/**
 * Evaluates whether a pull request matches a repository rule for a given trigger.
 * Author logins and label names are compared case-insensitively (matching GitHub semantics).
 */
export function evaluateRepoRule(
  rule: RepoRule,
  pr: PullRequestInfo,
  trigger: TriggerKind,
): RuleMatchResult {
  if (!rule.enabled) {
    return { matched: false, reason: 'rule_disabled' };
  }
  if (!rule.triggerOn.includes(trigger)) {
    return { matched: false, reason: `trigger_${trigger}_not_enabled` };
  }
  if (rule.ignoreDrafts && pr.draft) {
    return { matched: false, reason: 'draft_ignored' };
  }

  if (rule.baseBranches.length > 0 && !rule.baseBranches.includes(pr.baseBranch)) {
    return { matched: false, reason: `base_branch_${pr.baseBranch}_not_matched` };
  }

  const authorLower = pr.author.trim().toLowerCase();
  if (rule.authorAllowlist.length > 0) {
    const allowed = rule.authorAllowlist.some(a => a.trim().toLowerCase() === authorLower);
    if (!allowed) {
      return { matched: false, reason: 'author_not_in_allowlist' };
    }
  }
  if (rule.authorDenylist.length > 0) {
    const denied = rule.authorDenylist.some(a => a.trim().toLowerCase() === authorLower);
    if (denied) {
      return { matched: false, reason: 'author_in_denylist' };
    }
  }

  const prLabelsLower = new Set(pr.labels.map(l => l.trim().toLowerCase()));
  if (rule.labelAllowlist.length > 0) {
    const hasAllowed = rule.labelAllowlist.some(l => prLabelsLower.has(l.trim().toLowerCase()));
    if (!hasAllowed) {
      return { matched: false, reason: 'label_not_in_allowlist' };
    }
  }
  if (rule.labelDenylist.length > 0) {
    const hasDenied = rule.labelDenylist.some(l => prLabelsLower.has(l.trim().toLowerCase()));
    if (hasDenied) {
      return { matched: false, reason: 'label_in_denylist' };
    }
  }

  return { matched: true };
}

export function buildNewCommitMessage(
  pr: PullRequestInfo,
  previousHeadSha: string,
): string {
  const safeTitle = sanitizeUntrustedText(pr.title, {
    allowNewlines: false,
    maxCodePoints: 180,
    stripAngleBrackets: true,
    neutralizeMentions: true,
  });
  const header = [
    `[GitHub Update] New commit pushed to ${pr.repo}#${pr.number}`,
    `Previous SHA: ${previousHeadSha.slice(0, 12)} -> New SHA: ${pr.headSha.slice(0, 12)}`,
    `Title: ${safeTitle}`,
    '',
    '',
  ].join('\n');
  const maxXmlBytes = Math.max(512, MAX_IPC_TEXT_BYTES - Buffer.byteLength(header, 'utf8'));
  const xml = fitUntrustedPrMetadataXml(pr, maxXmlBytes, 500);
  return `${header}${xml}`;
}

export function buildPrClosedMessage(pr: PullRequestInfo): string {
  const statusLabel = pr.merged ? 'merged' : 'closed';
  const safeTitle = sanitizeUntrustedText(pr.title, {
    allowNewlines: false,
    maxCodePoints: 180,
    stripAngleBrackets: true,
    neutralizeMentions: true,
  });
  const safeAuthor = sanitizeUntrustedText(pr.author, {
    allowNewlines: false,
    maxCodePoints: 64,
    stripAngleBrackets: true,
    neutralizeMentions: true,
  });
  const safeUrl = sanitizeSafeHttpUrl(pr.htmlUrl);
  const msg = [
    `[GitHub Update] Pull request ${pr.repo}#${pr.number} was ${statusLabel}.`,
    `Author: ${safeAuthor}`,
    `Head SHA: ${pr.headSha.slice(0, 12)}`,
    `Title: ${safeTitle}`,
    safeUrl ? `URL: ${safeUrl}` : '',
  ]
    .filter(Boolean)
    .join('\n');
  return truncateUtf8Bytes(msg, MAX_IPC_TEXT_BYTES);
}
