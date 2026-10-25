import type { Rule } from '../types.js';
import { codeRules } from './code.js';
import { configRules } from './config.js';
import { secretRules } from './secrets.js';
import { textRules } from './text.js';

export const allRules: readonly Rule[] = [...textRules, ...codeRules, ...secretRules, ...configRules];

export function getRule(id: string): Rule | undefined {
  return allRules.find((rule) => rule.id === id);
}
