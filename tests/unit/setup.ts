import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// Utan globals körs inte RTL:s automatiska städning – gör den explicit.
afterEach(() => cleanup());
