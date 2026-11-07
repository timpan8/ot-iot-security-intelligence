import type {
  FactorLevel,
  InitialPasswordType,
  PublicPocStatus,
  RegisterOrigin,
  VerificationStatus,
} from '@schemas/index';
import {
  factorLabel,
  originLabel,
  originShort,
  pocStatusLabel,
  pocStatusShort,
  pwdTypeDescription,
  pwdTypeLabel,
  verificationDescription,
  verificationLabel,
} from '@/lib/labels';

type Tone = 'ok' | 'info' | 'warn' | 'neutral' | 'danger';

const toneClass: Record<Tone, string> = {
  ok: 'bg-ok-bg text-ok border-ok/30',
  info: 'bg-info-bg text-info border-info/30',
  warn: 'bg-warn-bg text-warn border-warn/30',
  neutral: 'bg-neutral-bg text-neutral border-neutral/30',
  danger: 'bg-danger-bg text-danger border-danger/30',
};

export function Badge({
  tone = 'neutral',
  children,
  title,
}: {
  tone?: Tone;
  children: React.ReactNode;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${toneClass[tone]}`}
    >
      {children}
    </span>
  );
}

const verificationTone: Record<VerificationStatus, Tone> = {
  verified_primary: 'ok',
  corroborated_secondary: 'info',
  needs_review: 'warn',
  unknown: 'neutral',
  disputed: 'danger',
};

export function VerificationBadge({ status }: { status: VerificationStatus }) {
  return (
    <Badge tone={verificationTone[status]} title={verificationDescription[status]}>
      {verificationLabel[status]}
    </Badge>
  );
}

const factorTone: Record<FactorLevel, Tone> = {
  high: 'danger',
  medium: 'warn',
  low: 'ok',
  unknown: 'neutral',
};

export function FactorBadge({ level }: { level: FactorLevel }) {
  return <Badge tone={factorTone[level]}>{factorLabel[level]}</Badge>;
}

const matchTone: Record<string, Tone> = {
  affected: 'danger',
  not_affected: 'ok',
  unknown: 'neutral',
  under_investigation: 'warn',
};
export function MatchStatusBadge({ status, label }: { status: string; label: string }) {
  return <Badge tone={matchTone[status] ?? 'neutral'}>{label}</Badge>;
}

const pwdTone: Record<InitialPasswordType, Tone> = {
  shared_default_documented: 'warn',
  default_exists_type_unknown: 'warn',
  device_unique_documented: 'ok',
  device_unique_normal_delivery: 'ok',
  model_version_batch_dependent: 'warn',
  version_dependent_shared_or_unique: 'warn',
  set_at_commissioning: 'ok',
  hardcoded_in_affected_version: 'danger',
  predictable_builtin_mechanism: 'danger',
  not_applicable_implementation: 'neutral',
  unknown_unverified: 'neutral',
};
/** Typ av initiallösenord – alltid med text, aldrig bara färg. Inga lösenordsvärden. */
export function PwdTypeBadge({ type }: { type: InitialPasswordType }) {
  return (
    <Badge tone={pwdTone[type]} title={pwdTypeDescription[type]}>
      {pwdTypeLabel[type]}
    </Badge>
  );
}

const pocTone: Record<PublicPocStatus, Tone> = {
  poc_reported: 'warn',
  none_reported_at_assessment: 'neutral',
  unknown_missing: 'neutral',
  active_reported: 'danger',
};
export function PocBadge({ status, short = false }: { status: PublicPocStatus; short?: boolean }) {
  return (
    <Badge tone={pocTone[status]} title={pocStatusLabel[status]}>
      {short ? pocStatusShort[status] : pocStatusLabel[status]}
    </Badge>
  );
}

export function OriginBadge({ origin }: { origin: RegisterOrigin }) {
  return (
    <Badge tone={origin === 'new' ? 'info' : 'neutral'} title={originLabel[origin]}>
      {originShort[origin]}
    </Badge>
  );
}
