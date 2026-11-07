// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SafeLink } from '@/components/SafeLink';
import { isSafeHttpsUrl } from '@/lib/url';

describe('SafeLink', () => {
  it('renderar https-länk med säkra attribut', () => {
    render(<SafeLink href="https://example.com/x">Exempel</SafeLink>);
    const a = screen.getByRole('link', { name: /Exempel/ });
    expect(a).toHaveAttribute('href', 'https://example.com/x');
    expect(a).toHaveAttribute('rel', 'noopener noreferrer');
    expect(a).toHaveAttribute('target', '_blank');
  });
  it.each([
    'http://example.com',
    'javascript:alert(1)',
    'data:text/html,hej',
    'ftp://x',
    'inte-en-url',
    '',
  ])('blockerar osäker URL: %s', (url) => {
    render(<SafeLink href={url}>Text</SafeLink>);
    expect(screen.queryByRole('link')).toBeNull();
    expect(isSafeHttpsUrl(url)).toBe(false);
  });
  it('null blir text', () => {
    render(<SafeLink href={null} />);
    expect(screen.getByText('Uppgift saknas')).toBeInTheDocument();
  });
});
