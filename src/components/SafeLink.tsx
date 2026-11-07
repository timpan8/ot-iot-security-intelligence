import type { ReactNode } from 'react';
import { isSafeHttpsUrl } from '@/lib/url';

/**
 * Renderar en extern länk endast om URL:en är https://. Andra scheman
 * (http, javascript, data …) renderas som ren text för att undvika
 * oavsiktlig navigering till osäkra mål.
 */
export function SafeLink({
  href,
  children,
  className,
}: {
  href: string | null | undefined;
  children?: ReactNode;
  className?: string;
}) {
  if (!isSafeHttpsUrl(href)) {
    return (
      <span className={className} data-unsafe-url="true">
        {children ?? href ?? 'Uppgift saknas'}
      </span>
    );
  }
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      referrerPolicy="no-referrer"
      className={className ?? 'underline break-all'}
    >
      {children ?? href}
      <span className="sr-only"> (öppnas i ny flik)</span>
    </a>
  );
}
