/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Utility functions for URL processing and normalization
 */

/**
 * Normalizes a URL to prevent common issues like double protocols
 * @param url The URL to normalize
 * @returns Normalized URL
 */
export function normalizeUrl(url: string): string {
  if (!url || typeof url !== 'string') {
    return url;
  }

  // Remove any trailing whitespace
  url = url.trim();

  // Fix double protocol issue (http://http://example.com -> http://example.com)
  url = url.replace(/^(https?:\/\/)(https?:\/\/)/i, '$1');

  // Ensure protocol exists for domain-only inputs
  if (!url.match(/^https?:\/\//i) && url.match(/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/)) {
    url = `http://${url}`;
  }

  // Remove trailing slash if not root
  if (url.endsWith('/') && url.length > 1 && url.split('/').length === 4) {
    url = url.slice(0, -1);
  }

  return url;
}

/**
 * Validates if a string is a valid URL
 * @param url The URL to validate
 * @returns True if valid, false otherwise
 */
export function isValidUrl(url: string): boolean {
  try {
    const normalizedUrl = normalizeUrl(url);
    new URL(normalizedUrl);
    return true;
  } catch {
    return false;
  }
}

/**
 * Extracts domain from URL
 * @param url The URL to extract domain from
 * @returns Domain name or null if invalid
 */
export function extractDomain(url: string): string | null {
  try {
    const normalizedUrl = normalizeUrl(url);
    const urlObj = new URL(normalizedUrl);
    return urlObj.hostname;
  } catch {
    return null;
  }
}

/**
 * Combines base URL with endpoint path safely
 * @param baseUrl Base URL
 * @param endpoint Endpoint path
 * @returns Combined URL
 */
export function combineUrl(baseUrl: string, endpoint: string): string {
  try {
    const normalizedBase = normalizeUrl(baseUrl);
    const url = new URL(endpoint, normalizedBase);
    return url.toString();
  } catch {
    // Fallback to simple concatenation if URL construction fails
    const normalizedBase = normalizeUrl(baseUrl);
    const separator = normalizedBase.endsWith('/') || endpoint.startsWith('/') ? '' : '/';
    return normalizedBase + separator + endpoint;
  }
}

/**
 * Converts a URL to a format suitable for security testing
 * @param url Input URL
 * @returns Security-test ready URL
 */
export function prepareUrlForSecurityTest(url: string): string {
  const normalized = normalizeUrl(url);
  
  // Ensure we have a valid URL for security testing
  if (!isValidUrl(normalized)) {
    throw new Error(`Invalid URL for security testing: ${url}`);
  }
  
  return normalized;
}
