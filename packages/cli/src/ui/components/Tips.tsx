/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { Box, Text } from 'ink';
import { Colors } from '../colors.js';
import { type Config } from '@conqxeror/aptx-cli-core';

interface TipsProps {
  config: Config;
}

export const Tips: React.FC<TipsProps> = ({ config }) => {
  const geminiMdFileCount = config.getGeminiMdFileCount();
  return (
    <Box flexDirection="column">
      <Text color={Colors.Foreground}>🎯 APTX CLI - Elite Penetration Testing Tips:</Text>
      <Text color={Colors.Foreground}>
        1. 🧘‍♂️ Try{' '}
        <Text bold color={Colors.AccentPurple}>
          monk mode
        </Text>{' '}
        for elite vulnerability hunting on targets
      </Text>
      <Text color={Colors.Foreground}>
        2. 🔍 Ask: "Scan target https://example.com for OWASP Top 10 vulnerabilities"
      </Text>
      <Text color={Colors.Foreground}>
        3. 🛠️ Use{' '}
        <Text bold color={Colors.AccentPurple}>
          /install
        </Text>{' '}
        to auto-install security tools (nmap, nikto, sqlmap, etc.)
      </Text>
      {geminiMdFileCount === 0 && (
        <Text color={Colors.Foreground}>
          4. 📝 Create{' '}
          <Text bold color={Colors.AccentPurple}>
            monkMode.md
          </Text>{' '}
          files to customize your penetration testing workflows
        </Text>
      )}
      <Text color={Colors.Foreground}>
        {geminiMdFileCount === 0 ? '5.' : '4.'}{' '}
        <Text bold color={Colors.AccentPurple}>
          /help
        </Text>{' '}
        for complete command reference and examples
      </Text>
    </Box>
  );
};
