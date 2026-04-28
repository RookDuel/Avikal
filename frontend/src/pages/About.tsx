import { useState, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { ChevronDown, ExternalLink, HelpCircle, Sparkles } from 'lucide-react'

type FaqItem = {
  question: string
  body: ReactNode
}

function CodeToken({ children }: { children: ReactNode }) {
  return (
    <code className="rounded-md border border-av-border/50 bg-av-border/10 px-1.5 py-0.5 font-mono text-[12px] text-av-main">
      {children}
    </code>
  )
}

function FaqParagraph({ children }: { children: ReactNode }) {
  return <p className="text-[14px] leading-7 text-av-main">{children}</p>
}

function FaqList({ children }: { children: ReactNode }) {
  return <ul className="space-y-3">{children}</ul>
}

function FaqBullet({
  label,
  children,
}: {
  label: ReactNode
  children: ReactNode
}) {
  return (
    <li className="flex items-start gap-3 rounded-2xl border border-av-border/35 bg-av-border/6 px-4 py-3">
      <span className="mt-2 h-2 w-2 shrink-0 rounded-full bg-av-accent" />
      <p className="text-[14px] leading-7 text-av-main">
        <span className="font-semibold">{label}</span> {children}
      </p>
    </li>
  )
}

const faqs: FaqItem[] = [
  {
    question: '1. What are the different "Protection Models" available in RookDuel Avikal?',
    body: (
      <div className="space-y-4">
        <FaqParagraph>
          RookDuel Avikal offers four primary ways to control how an archive is protected. These are logic
          models for access control rather than just simple algorithm choices:
        </FaqParagraph>
        <FaqList>
          <FaqBullet label="Standard Archive:">Portable, universal access.</FaqBullet>
          <FaqBullet label="Access Password:">Human-defined secret.</FaqBullet>
          <FaqBullet label="Security Keyphrase:">21-word mnemonic secret.</FaqBullet>
          <FaqBullet label="Quantum Keyfile:">Physical "hardware-style" file dependency.</FaqBullet>
        </FaqList>
      </div>
    ),
  },
  {
    question: '2. Is a "Standard Archive" actually encrypted?',
    body: (
      <div className="space-y-4">
        <FaqParagraph>
          Yes, but it is not "private." Even without a password, RookDuel Avikal runs the full pipeline: it
          compresses the data, adds random padding, and creates the <CodeToken>.enc</CodeToken> and{' '}
          <CodeToken>.pgn</CodeToken> structures.
        </FaqParagraph>
        <FaqList>
          <FaqBullet label="The Mechanism:">
            Because no user secret is provided, it falls back to a built-in, public protection
            secret.
          </FaqBullet>
          <FaqBullet label="Purpose:">
            Use this for <strong>portability and containerization</strong> (like a ZIP file) when
            you want the RookDuel Avikal format but don't need to hide contents from the public.
          </FaqBullet>
        </FaqList>
      </div>
    ),
  },
  {
    question: '3. How does the "Access Password" layer work?',
    body: (
      <div className="space-y-4">
        <FaqParagraph>This is the standard human-secret lock.</FaqParagraph>
        <FaqList>
          <FaqBullet label="Strength:">
            The system enforces a strength check before encoding.
          </FaqBullet>
          <FaqBullet label="Cryptography:">
            It uses <strong>Argon2id</strong> for key derivation and <strong>HKDF</strong> for
            expansion.
          </FaqBullet>
          <FaqBullet label="Protection:">
            It secures both the payload and the hidden chess metadata. Without the correct password,
            the archive cannot be decoded.
          </FaqBullet>
        </FaqList>
      </div>
    ),
  },
  {
    question: '4. What makes the "Security Keyphrase" unique?',
    body: (
      <div className="space-y-4">
        <FaqParagraph>
          The keyphrase serves as a high-entropy, human-readable secret.
        </FaqParagraph>
        <FaqList>
          <FaqBullet label="Devnagri Implementation:">
            RookDuel Avikal generates a unique <strong>21-word keyphrase</strong> using the Devnagri script.
          </FaqBullet>
          <FaqBullet label="The Math:">
            The backend uses a frozen <strong>2048-word canonical list</strong>. The generated phrase is
            checksum-validated and the total possible combinations ($2048^{'{'}21{'}'}$) remain far beyond
            practical brute-force range.
          </FaqBullet>
          <FaqBullet label="Security:">
            This is a real cryptographic factor; it is normalized, validated, and then fed into the same
            derivation flow as a password.
          </FaqBullet>
        </FaqList>
      </div>
    ),
  },
  {
    question: '5. What is the "Quantum Keyfile" layer?',
    body: (
      <div className="space-y-4">
        <FaqParagraph>
          This is an advanced security layer that adds an external physical dependency.
        </FaqParagraph>
        <FaqList>
          <FaqBullet label="Hybrid Security:">
            It must be layered on top of a password or keyphrase; it cannot be a standalone mode.
          </FaqBullet>
          <FaqBullet label="The .avkkey File:">
            RookDuel Avikal generates a separate file containing private Post-Quantum Cryptography (PQC)
            material.
          </FaqBullet>
          <FaqBullet label="Security Benefit:">
            The private "unlocking" material is kept <strong>outside</strong> the archive. Even if
            the <CodeToken>.avk</CodeToken> file is compromised, it cannot be opened without the
            physical <CodeToken>.avkkey</CodeToken> file.
          </FaqBullet>
        </FaqList>
      </div>
    ),
  },
  {
    question: '6. How does the "Time-Capsule" layer control access?',
    body: (
      <div className="space-y-4">
        <FaqParagraph>
          This layer controls <strong>when</strong> an archive can be opened using "split-key"
          logic. The second half of the key (Key B) is retrieved via:
        </FaqParagraph>
        <FaqList>
          <FaqBullet label="Custom Aavrit:">
            Key B is held behind the external Aavrit release authority and is released
            only after the configured unlock time and any required user authentication.
          </FaqBullet>
          <FaqBullet label="drand:">
            A decentralized, public alternative for time-locking.
          </FaqBullet>
        </FaqList>
      </div>
    ),
  },
  {
    question: '7. What is "drand" and how does it work?',
    body: (
      <div className="space-y-4">
        <FaqParagraph>
          <strong>drand</strong> (distributed randomness) is a protocol providing publicly
          verifiable randomness at fixed intervals.
        </FaqParagraph>
        <FaqList>
          <FaqBullet label="Decentralized Logic:">
            A network of independent nodes (like Cloudflare and EPFL) produces a "beacon" at
            specific intervals.
          </FaqBullet>
          <FaqBullet label="RookDuel Avikal Integration:">
            RookDuel Avikal uses a future drand signature as the encryption key. Since no one knows the
            future signature until the network generates it at the exact timestamp, the archive is
            mathematically locked until that moment. It is free, anonymous, and supports unlimited
            capsules.
          </FaqBullet>
        </FaqList>
      </div>
    ),
  },
]

export default function About() {
  const [openIndex, setOpenIndex] = useState<number>(0)

  const handleOpenWebsite = async () => {
    const url = 'https://avikal.rookduel.tech'

    if (window.electron?.openExternal) {
      await window.electron.openExternal(url)
      return
    }

    window.open(url, '_blank', 'noopener,noreferrer')
  }

  return (
    <div className="min-h-full w-full max-w-[1180px] mx-auto px-6 py-8 lg:px-10 lg:py-10">
      <div className="space-y-6">
        <motion.section
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="relative overflow-hidden rounded-[32px] border border-av-border/50 bg-av-surface/80 shadow-[0_18px_42px_rgba(0,0,0,0.06)] backdrop-blur-2xl"
        >
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(58,87,232,0.12),transparent_36%),radial-gradient(circle_at_bottom_right,rgba(14,165,233,0.08),transparent_34%)] dark:bg-[radial-gradient(circle_at_top_left,rgba(59,130,246,0.16),transparent_36%),radial-gradient(circle_at_bottom_right,rgba(56,189,248,0.10),transparent_34%)]" />
          <div className="relative grid gap-6 p-8 lg:grid-cols-[1.2fr_0.8fr] lg:p-10">
            <div className="space-y-4">
              <div className="inline-flex items-center gap-2 rounded-full border border-av-border/60 bg-av-border/10 px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-av-muted">
                <Sparkles className="h-4 w-4 text-av-accent" />
                Project Note
              </div>
              <div className="space-y-3">
                <h1 className="text-3xl font-semibold tracking-tight text-av-main lg:text-5xl">
                  RookDuel Avikal
                </h1>
                <p className="max-w-2xl text-[15px] leading-8 text-av-main">
                  RookDuel Avikal is a Project under RookDuel, for more information user can visit
                  avikal.rookduel.tech
                </p>
              </div>
            </div>

            <div className="flex items-end">
              <button
                type="button"
                onClick={handleOpenWebsite}
                className="group w-full rounded-[24px] border border-av-border/60 bg-av-surface/85 p-5 text-left shadow-[0_12px_28px_rgba(0,0,0,0.05)] transition-all hover:-translate-y-0.5 hover:border-av-accent/40 hover:shadow-[0_18px_36px_rgba(0,0,0,0.08)]"
              >
                <p className="text-[11px] font-semibold uppercase tracking-[0.2em] text-av-muted">
                  Official Website
                </p>
                <div className="mt-3 flex items-center justify-between gap-4">
                  <div>
                    <p className="text-lg font-semibold text-av-main">avikal.rookduel.tech</p>
                  </div>
                  <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-av-border/60 bg-av-border/10 text-av-main transition-colors group-hover:text-av-accent">
                    <ExternalLink className="h-5 w-5" />
                  </div>
                </div>
              </button>
            </div>
          </div>
        </motion.section>

        <motion.section
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.05 }}
          className="overflow-hidden rounded-[32px] border border-av-border/50 bg-av-surface/82 shadow-[0_18px_42px_rgba(0,0,0,0.06)] backdrop-blur-2xl"
        >
          <div className="border-b border-av-border/40 bg-av-border/10 px-8 py-6">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-av-border/50 bg-av-surface/80">
                <HelpCircle className="h-5 w-5 text-av-accent" />
              </div>
              <div>
                <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-av-muted">
                  FAQ
                </p>
                <h2 className="text-2xl font-semibold tracking-tight text-av-main">
                  Avikal Archive & Encryption: Frequently Asked Questions
                </h2>
              </div>
            </div>
          </div>

          <div className="grid gap-4 px-6 py-6 lg:px-8 lg:py-8">
            {faqs.map((item, index) => {
              const isOpen = openIndex === index

              return (
                <motion.article
                  key={item.question}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.28, delay: index * 0.03 }}
                  className={`overflow-hidden rounded-[24px] border transition-all ${
                    isOpen
                      ? 'border-av-accent/35 bg-av-border/10 shadow-[0_14px_32px_rgba(0,0,0,0.05)]'
                      : 'border-av-border/50 bg-av-surface/70 hover:border-av-border/80 hover:bg-av-border/6'
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => setOpenIndex(isOpen ? -1 : index)}
                    className="flex w-full items-start gap-4 p-5 text-left lg:p-6"
                  >
                    <div
                      className={`mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border text-sm font-semibold ${
                        isOpen
                          ? 'border-av-accent/30 bg-av-accent/10 text-av-accent'
                          : 'border-av-border/60 bg-av-border/10 text-av-main'
                      }`}
                    >
                      {index + 1}
                    </div>

                    <div className="min-w-0 flex-1">
                      <h3 className="text-[15px] font-semibold leading-7 text-av-main">
                        {item.question}
                      </h3>
                    </div>

                    <div
                      className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border transition-all ${
                        isOpen
                          ? 'border-av-accent/30 bg-av-accent/10 text-av-accent'
                          : 'border-av-border/60 bg-av-border/10 text-av-muted'
                      }`}
                    >
                      <ChevronDown
                        className={`h-5 w-5 transition-transform ${isOpen ? 'rotate-180' : ''}`}
                      />
                    </div>
                  </button>

                  {isOpen && (
                    <div className="border-t border-av-border/40 px-5 pb-5 pt-0 lg:px-6 lg:pb-6">
                      <div className="rounded-[20px] border border-av-border/40 bg-av-surface/70 p-5">
                        {item.body}
                      </div>
                    </div>
                  )}
                </motion.article>
              )
            })}
          </div>
        </motion.section>
      </div>
    </div>
  )
}
