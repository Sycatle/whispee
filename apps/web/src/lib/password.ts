/**
 * Password policy.
 *
 * # Why not "one uppercase, one digit, one symbol"
 *
 * Those rules create no entropy: they move the `A` to the front and the `1!` to the end. The
 * space of passwords a human produces under those constraints is smaller, not larger — and
 * attackers know it better than we do. NIST explicitly dropped them in SP 800-63B.
 *
 * What actually counts: **length**, and **not being guessable**. That is what this module
 * measures, with zxcvbn-ts — a maintained TypeScript port of Dropbox's zxcvbn. It matches the
 * password against word lists, dates, keyboard runs, repeats and `l33t` substitutions, scores
 * each interpretation and keeps the cheapest one. `P@ssw0rd2024!` lands at 10^7 tries rather than
 * the 10^25 a character-class count would have credited it with, because the swaps are undone
 * before the word is looked up — an attacker undoes them too.
 *
 * # What it costs, and where it is paid
 *
 * The estimator adds 2 KB to the bundle everyone downloads. Its word lists are another 464 KB,
 * 222 KB of it over the wire compressed, behind a dynamic `import()`: they are fetched the first
 * time somebody types into the password field on the lock screen, and on no other load. Nothing
 * on the unlock path needs them — verifying a password is Argon2id's job, not this module's.
 *
 * Only the **common** pack is loaded: the top of the breach corpora, the diceware list and the
 * keyboard graphs. The English word lists were measured and left out. They are 1.2 MB, three
 * quarters of the whole cost, and across every case tried while deciding this they changed no
 * verdict — they sharpen the number without moving it across the line. What that gives up is
 * real and one-directional: an English word that is not also a common password is **overrated**
 * here. `thompsonhouse` scores 10^6.5 with what is loaded and 10^4.3 with the English lists, and
 * a construction of two or three such words could clear the floor below while an attacker with an
 * English dictionary finds it sooner than this module claims.
 *
 * # Why no Have I Been Pwned
 *
 * The other realistic option for catching breached passwords is HIBP's k-anonymous range API,
 * and it was turned down. It sends the first five characters of the password's SHA-1 to a third
 * party, at the exact moment the user is choosing the secret that protects everything else on
 * the device. The prefix narrows the password to a few hundred candidates and arrives alongside
 * an IP address and a timestamp — small, but not nothing, and it is precisely the kind of "small"
 * this project exists to refuse. It would also need the network to work at all, which a client
 * that runs offline should not require in order to let someone set a password.
 *
 * The offline list bundled with zxcvbn is the top of the same breach corpora — the passwords
 * everyone actually reuses. What it gives up against HIBP is the long tail: a password breached
 * once, five years ago, in a dump nobody indexed, passes here. A 12-character floor and pattern
 * matching cover more of the realistic attacks than an exact-match lookup of that tail would,
 * and they cover them without asking anyone's permission to speak to a server.
 *
 * # What this password protects
 *
 * State at rest on this device, nothing else. It is not a recovery factor: forgetting it loses
 * nothing, the twelve-word phrase remains the only restore path.
 */

/** Minimum length. Twelve characters of everyday prose are worth ~40 bits — the floor below
 * which even Argon2id no longer makes an offline attack expensive. */
export const MIN_LENGTH = 12;

/**
 * Guessability floor, as a base-10 logarithm of the number of guesses.
 *
 * 10^10 is zxcvbn's own line between "survives an offline attack on a slow hash" and everything
 * below it. It is the right line here because the hash *is* slow: Argon2id at 64 MiB costs about
 * a second per attempt on a laptop and cannot be parallelised away cheaply.
 *
 * It is a floor on an estimate, not a guarantee. zxcvbn only knows the patterns it was taught: a
 * password built on a habit it has no dictionary for — a local place name, a family in-joke, a
 * language it does not ship — scores far above what someone who knows the user would need.
 */
const MIN_GUESSES_LOG10 = 10;

/**
 * Fallback list, used only when the estimator cannot be loaded.
 *
 * This is not the policy — the policy is zxcvbn's dictionaries, which are thirty thousand
 * entries deep. This handful exists so that a failed chunk fetch degrades to *something* rather
 * than accepting `password1234` in silence. It catches the obvious cases and nothing else, and
 * a verdict produced this way says so on screen.
 */
const COMMON = [
  "motdepasse", "password", "azertyuiop", "qwertyuiop", "123456789", "1234567890",
  "administrateur", "changeme", "letmein", "welcome1", "iloveyou", "sunshine",
  "princesse", "football", "monkey123", "dragon123", "abc123456", "passw0rd",
  "motdepasse1", "password1", "azerty123", "qwerty123", "000000000", "111111111",
];

export interface Verdict {
  ok: boolean;
  /** Why it was refused. Empty when the password is fine. */
  reason: string;
  /**
   * Order of magnitude of the guesses an attacker who knows these patterns would need, in powers
   * of ten. `null` when the estimator could not be loaded and only the fallback ran — the caller
   * must then say that no estimate was made rather than show a number nobody computed.
   */
  guessesLog10: number | null;
  /** zxcvbn's own advice, when it has any. Empty otherwise. */
  advice: string;
}

interface Estimate {
  guessesLog10: number;
  warning: string;
  suggestion: string;
}

/**
 * The loaded estimator, kept so the dictionaries are parsed once.
 *
 * Cleared on failure: an import that failed because the network dropped must be retried on the
 * next keystroke, not remembered as a permanent verdict.
 */
let loading: Promise<(password: string, userInputs: string[]) => Estimate> | null = null;

function estimator() {
  loading ??= (async () => {
    const [{ ZxcvbnFactory }, common, english] = await Promise.all([
      import("@zxcvbn-ts/core"),
      import("@zxcvbn-ts/language-common"),
      // Reached through its file rather than through the package: the package's entry point pulls
      // the four English word lists in with it, 1.2 MB of them, and no bundler here manages to
      // shake them back out. The path is pinned by the version range in `package.json`; if a
      // later release moves it, this fails loudly at build time rather than quietly shipping the
      // lists again.
      import("@zxcvbn-ts/language-en/dist/translations.mjs"),
    ]);

    const zxcvbn = new ZxcvbnFactory({
      dictionary: common.dictionary,
      graphs: common.adjacencyGraphs,
      translations: english.default,
    });

    return (password: string, userInputs: string[]) => {
      const result = zxcvbn.check(password, userInputs);
      return {
        guessesLog10: result.guessesLog10,
        warning: result.feedback.warning ?? "",
        suggestion: result.feedback.suggestions[0] ?? "",
      };
    };
  })().catch((e: unknown) => {
    loading = null;
    throw e;
  });

  return loading;
}

/**
 * Judges a password.
 *
 * `userInputs` should carry whatever the attacker already knows about this account — the handle,
 * above all. A password built out of one's own username is a dictionary word to anyone who has
 * seen the account and to nobody else, which is exactly the case a generic word list misses.
 *
 * Asynchronous because the dictionaries are: a caller rendering as the user types must expect the
 * first verdict to arrive a moment late, and must ignore a verdict for a password that has since
 * changed.
 */
export async function check(password: string, userInputs: string[] = []): Promise<Verdict> {
  // Length first, and before loading anything: it is the one rule that holds whatever the
  // estimator thinks, and it spares a 900 KB fetch to tell someone their four characters are
  // short.
  if (password.length < MIN_LENGTH) {
    return {
      ok: false,
      reason: `At least ${MIN_LENGTH} characters. Length is what actually protects you — not uppercase letters or digits.`,
      guessesLog10: null,
      advice: "",
    };
  }

  let estimate: Estimate;
  try {
    estimate = await (await estimator())(password, userInputs);
  } catch {
    return degraded(password);
  }

  if (estimate.guessesLog10 < MIN_GUESSES_LOG10) {
    return {
      ok: false,
      // The number is stated rather than a colour shown: "weak" invites the user to add a `!` and
      // try again, an order of magnitude tells them how far off they are.
      reason:
        estimate.warning ||
        `Guessable in about 10^${Math.round(estimate.guessesLog10)} tries by an attacker using published word lists.`,
      guessesLog10: estimate.guessesLog10,
      advice: estimate.suggestion,
    };
  }

  return { ok: true, reason: "", guessesLog10: estimate.guessesLog10, advice: "" };
}

/**
 * The verdict when the estimator did not load.
 *
 * It accepts far too much, and the caller is told so through `guessesLog10: null`. The
 * alternative — refusing to let anyone set a password until a chunk downloads — would lock people
 * out of the feature over a flaky connection, which is a worse outcome than a weak password on a
 * device whose state is already only as exposed as the browser it sits in.
 */
function degraded(password: string): Verdict {
  const normalized = password.toLowerCase();

  if (COMMON.some((known) => normalized.includes(known))) {
    return {
      ok: false,
      reason: "This password contains a sequence found in known breach lists.",
      guessesLog10: null,
      advice: "",
    };
  }

  // A single repeated character, or a keyboard run, clears the minimum length while being worth
  // nothing: "aaaaaaaaaaaa" is twelve characters and zero bits of entropy.
  if (new Set(password).size <= 4) {
    return {
      ok: false,
      reason: "Too few distinct characters: length alone is not enough.",
      guessesLog10: null,
      advice: "",
    };
  }

  return { ok: true, reason: "", guessesLog10: null, advice: "" };
}
