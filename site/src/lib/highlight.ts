/**
 * Token classes, from the compiler's own lexer.
 *
 * There is no grammar in this repository's website. `site/records/highlight.json`
 * holds one HTML string per file, produced by
 * `Crystal::SyntaxHighlighter::HTML` running inside the iyi fork's own
 * compiler, which means the tokens on the page are the tokens the compiler saw.
 * A hand written scanner would be a second grammar, it would drift from the
 * first one silently, and the drift would show up as a keyword the site does
 * not think is a keyword. So there is one grammar and it is the compiler's.
 *
 * The lexer's classes, and what each one is:
 *
 *   k  keyword, and `self`
 *   t  a constant or type name
 *   m  an identifier: a method name at its definition or its call
 *   s  a string or a character literal
 *   n  a number, a symbol, or a primitive literal
 *   o  an operator or a delimiter
 *   c  a comment
 *   i  the delimiters of a string interpolation
 *
 * The lexer does not distinguish iyi's keywords from Crystal's, because to the
 * lexer they are all keywords, and that distinction is the whole argument the
 * site's listings are making. So `site/scripts/record-highlight.mjs` adds
 * `tok-rule` to the `k` spans whose text is one of iyi's own keywords, AFTER
 * the lexer has decided where the tokens are. The split is applied to a class
 * attribute, never to a token boundary, so the emphasis cannot invent a token
 * the compiler did not see. `site/src/styles/code.css` carries the weight for
 * both.
 *
 * WHAT THIS MODULE IS FOR: a record is one HTML string per whole file, and a
 * listing on this site is usually a slice of a file. Splitting an HTML string
 * on newlines is only correct if no element crosses one, and elements do cross
 * one: `samples/iyi/calc.iyi` holds a multi line string literal, so the lexer
 * emits a single `s` span containing newlines. Slicing that naively yields
 * unbalanced HTML, which a browser then repairs by guessing, and the guess is
 * a listing that is silently wrong below the cut.
 *
 * So this module reparses the record into tokens and re emits it one line at a
 * time, closing every open element at a line break and reopening it on the
 * next line. The result is that every line is independently balanced and any
 * contiguous run of lines can be concatenated. It verifies as it goes: the text
 * recovered from the record must be exactly the file's own text, and a record
 * that does not satisfy that fails the build naming the file.
 */
import record from "../../records/highlight.json";

interface HighlightRecord {
  recorded: {
    compiler: string;
    commit: string;
    machine: string;
    command: string;
    when: string;
  };
  files: Record<string, string>;
}

const highlights = record as HighlightRecord;

/**
 * The provenance of the recording, exported so a page can stamp it. Checked
 * once here rather than at every use, because a record with no provenance is
 * not a record and the build should stop at the first import of it.
 */
export const highlightProvenance = highlights.recorded;

for (const field of ["compiler", "commit", "machine", "command", "when"] as const) {
  if (!highlightProvenance?.[field]) {
    throw new Error(
      `highlight: site/records/highlight.json has no "recorded.${field}". ` +
        `A record without its provenance is an assertion, and this site does ` +
        `not render assertions. Regenerate it with ` +
        `${highlightProvenance?.command ?? "the recorder script"}.`,
    );
  }
}

/** One lexed token: the class the compiler gave it, and its literal text. */
interface Token {
  /** The class attribute verbatim, so a `k tok-rule` split survives. Empty
   * for text the lexer did not classify, which is whitespace and punctuation
   * it does not tokenise. */
  cls: string;
  text: string;
}

const UNESCAPE: Record<string, string> = {
  "&amp;": "&",
  "&lt;": "<",
  "&gt;": ">",
  "&quot;": '"',
  "&#39;": "'",
};

const ESCAPE: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/**
 * Reparse the recorded HTML into tokens.
 *
 * The recorded shape is flat by construction: the highlighter emits
 * `<span class="x">text</span>` and bare text, and never nests one span inside
 * another. This asserts that rather than assuming it, because a nested span
 * would make the reflow below drop a class and the listing would lose emphasis
 * with no error anywhere.
 */
function lex(html: string, path: string): Token[] {
  const tokens: Token[] = [];
  const pattern = /<span class="([^"]*)">|<\/span>/g;
  let at = 0;
  let open: string | null = null;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(html)) !== null) {
    const text = html.slice(at, match.index);
    if (text.length > 0) tokens.push({ cls: open ?? "", text });
    at = match.index + match[0].length;

    if (match[0] === "</span>") {
      if (open === null) {
        throw new Error(
          `highlight: the record for ${path} closes a span that was never ` +
            `opened, at character ${match.index}. The record is malformed.`,
        );
      }
      open = null;
    } else {
      if (open !== null) {
        throw new Error(
          `highlight: the record for ${path} nests a "${match[1]}" span ` +
            `inside an open "${open}" span, at character ${match.index}. This ` +
            `module reflows a flat token stream and would drop the outer ` +
            `class, so a nested record is a build failure rather than a ` +
            `listing that quietly loses its emphasis.`,
        );
      }
      open = match[1];
    }
  }

  if (open !== null) {
    throw new Error(
      `highlight: the record for ${path} ends inside an open "${open}" span. ` +
        `The record is malformed.`,
    );
  }
  const tail = html.slice(at);
  if (tail.length > 0) tokens.push({ cls: "", text: tail });
  return tokens;
}

/**
 * Re emit tokens one line at a time.
 *
 * A token carrying newlines is split at each one and its element is closed and
 * reopened, so every returned line is independently balanced HTML and any run
 * of them concatenates correctly. This is the whole reason this module exists.
 */
function reflow(tokens: readonly Token[]): string[] {
  const lines: string[] = [];
  let current = "";

  for (const token of tokens) {
    const pieces = token.text.split("\n");
    for (let i = 0; i < pieces.length; i += 1) {
      if (i > 0) {
        lines.push(current);
        current = "";
      }
      const piece = pieces[i];
      if (piece.length === 0) continue;
      current +=
        token.cls === ""
          ? piece
          : `<span class="${token.cls}">${piece}</span>`;
    }
  }
  lines.push(current);
  return lines;
}

/** Cached per path: a listing may be sliced several times on one page. */
const reflowed: Record<string, string[]> = {};

/**
 * The recorded highlighting for one file, one balanced HTML string per line.
 *
 * `path` is the repository relative path, which is exactly the key the recorder
 * writes, so `samples/iyi/hello.iyi` and `site/records/break/r2.iyi` both
 * resolve through this one call.
 *
 * An absent path is a build failure and never a plain text fallback. Falling
 * back would make one listing on the site the only one without the emphasis
 * that carries the argument, and it would do it silently, which is the exact
 * failure mode this site is arranged to prevent.
 */
export function highlightedLines(path: string): string[] {
  const cached = reflowed[path];
  if (cached !== undefined) return cached;

  const html = highlights.files[path];
  if (html === undefined) {
    const known = Object.keys(highlights.files);
    throw new Error(
      `highlight: site/records/highlight.json has no entry for "${path}". ` +
        `Token classes on this site come from the compiler's own lexer, so a ` +
        `file with no record cannot be rendered as code, and rendering it as ` +
        `plain text would make it the one listing without the emphasis that ` +
        `carries the argument. It records ${known.length} files: ` +
        `${known.slice(0, 8).join(", ")}${known.length > 8 ? ", ..." : ""}. ` +
        `Regenerate with ${highlightProvenance.command}.`,
    );
  }

  const lines = reflow(lex(html, path));
  reflowed[path] = lines;
  return lines;
}

/**
 * The text the record encodes, recovered by stripping tags and unescaping.
 *
 * This exists so a caller can prove the record still describes the file it
 * claims to. `Sample.astro` compares it against the file the samples index
 * read, so a record that went stale against an edited sample fails the build
 * instead of highlighting the wrong tokens over the right text.
 */
export function recordedText(path: string): string {
  return highlightedLines(path)
    .join("\n")
    .replace(/<\/?span[^>]*>/g, "")
    .replace(/&(?:amp|lt|gt|quot|#39);/g, (entity) => UNESCAPE[entity]);
}

/**
 * Escape source text for insertion beside recorded HTML.
 *
 * Used where a page renders text the record does not cover, so both halves are
 * escaped by the same rules and a stray `<` cannot become markup.
 */
export function escapeCode(text: string): string {
  return text.replace(/[&<>"']/g, (char) => ESCAPE[char]);
}
