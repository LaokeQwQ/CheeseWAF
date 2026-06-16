type MarkdownBlock =
  | { type: 'paragraph'; text: string }
  | { type: 'heading'; level: number; text: string }
  | { type: 'list'; items: string[] }
  | { type: 'table'; headers: string[]; rows: string[][] };

type Props = {
  text: string;
  className?: string;
};

export default function SafeMarkdown({ text, className = '' }: Props) {
  const blocks = parseMarkdownBlocks(text);
  return (
    <div className={['assistant-markdown', className].filter(Boolean).join(' ')}>
      {blocks.map((block, index) => {
        if (block.type === 'table') {
          return (
            <div className="assistant-markdown-table-wrap" key={`table-${index}`}>
              <table>
                <thead>
                  <tr>{block.headers.map((cell, cellIndex) => <th key={`${cellIndex}-${cell}`}>{renderInlineMarkdown(cell)}</th>)}</tr>
                </thead>
                <tbody>
                  {block.rows.map((row, rowIndex) => (
                    <tr key={`row-${rowIndex}`}>
                      {row.map((cell, cellIndex) => <td key={`${rowIndex}-${cellIndex}`}>{renderInlineMarkdown(cell)}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }
        if (block.type === 'list') {
          return <ul key={`list-${index}`}>{block.items.map((item) => <li key={item}>{renderInlineMarkdown(item)}</li>)}</ul>;
        }
        if (block.type === 'heading') {
          const Heading = `h${Math.min(4, Math.max(3, block.level))}` as 'h3' | 'h4';
          return <Heading key={`heading-${index}`}>{renderInlineMarkdown(block.text)}</Heading>;
        }
        return <p key={`p-${index}`}>{renderInlineMarkdown(block.text)}</p>;
      })}
    </div>
  );
}

function parseMarkdownBlocks(value: string): MarkdownBlock[] {
  const lines = stripInternalProcessPhrases(normalizeMarkdownForAssistant(value)).split('\n');
  const blocks: MarkdownBlock[] = [];
  let paragraph: string[] = [];
  let list: string[] = [];
  const flushParagraph = () => {
    if (paragraph.length > 0) {
      blocks.push({ type: 'paragraph', text: paragraph.join('\n').trim() });
      paragraph = [];
    }
  };
  const flushList = () => {
    if (list.length > 0) {
      blocks.push({ type: 'list', items: list });
      list = [];
    }
  };
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (!line) {
      flushParagraph();
      flushList();
      continue;
    }
    const heading = /^(#{1,4})\s+(.+)$/.exec(line);
    if (heading) {
      flushParagraph();
      flushList();
      blocks.push({ type: 'heading', level: heading[1].length, text: heading[2].trim() });
      continue;
    }
    if (isMarkdownTableStart(lines, index)) {
      flushParagraph();
      flushList();
      const headers = parseTableRow(lines[index]);
      index += 2;
      const rows: string[][] = [];
      while (index < lines.length && isTableRow(lines[index])) {
        rows.push(parseTableRow(lines[index]));
        index += 1;
      }
      index -= 1;
      blocks.push({ type: 'table', headers, rows });
      continue;
    }
    const listItem = /^[-*]\s+(.+)$/.exec(line);
    if (listItem) {
      flushParagraph();
      list.push(listItem[1].trim());
      continue;
    }
    flushList();
    paragraph.push(line);
  }
  flushParagraph();
  flushList();
  return blocks.length > 0 ? blocks : [{ type: 'paragraph', text: '' }];
}

export function stripInternalProcessPhrases(value: string) {
  const cleaned = value
    .replace(/（基于(?:工具结果|查询结果|返回结果|工具\s*observation|observation)）/gi, '')
    .replace(/基于(?:工具结果|查询结果|返回结果|工具\s*observation|observation)[，,：:\s]*/gi, '')
    .replace(/根据\s*`?recent_security_events`?\s*(?:工具\s*)?返回的(?:最近\s*)?(?:\d+\s*条)?(?:事件|结果)?(?:（[^）]*）)?[，,：:\s]*/g, '')
    .replace(/根据\s*`?recent_security_events`?\s*(?:工具\s*)?返回的[，,：:\s]*/g, '')
    .replace(/\baccording to\s+`?recent_security_events`?\s+(?:tool\s+)?(?:result|results|return|returned)[,:\s]*/gi, '')
    .replace(/\bbased on\s+(?:tool\s+)?(?:result|results|observations?)[,:\s]*/gi, '')
    .replace(/真实工具\s*observation/gi, '真实数据')
    .replace(/工具\s*observation/gi, '真实数据')
    .replace(/\btool\s+observations?\b/gi, 'data')
    .replace(/\bobservations?\b/gi, 'data')
    .replace(/基于\s*(?:data|数据)\s*汇总[，,：:\s]*/gi, '')
    .replace(/(?:先)?调用工具[，,。；;:\s]*/g, '')
    .replace(/(?:^|\n)\s*(?:执行过程|系统提示词|提示词)[：:][^\n]*(?:\n|$)/g, '\n')
    .replace(/(?:执行过程|系统提示词|提示词)[：:][^\n]*/g, '')
    .replace(/(?:^|\n)\s*(?:execution process|internal process|system prompt|prompt text)\s*:[^\n]*(?:\n|$)/gi, '\n')
    .replace(/(?:execution process|internal process|system prompt|prompt text)\s*:[^\n]*/gi, '')
    .replace(/\btool\s+calls?\b[.,;:\s]*/gi, '')
    .replace(/`?recent_security_events`?\s*(?:工具|tool)?/gi, '安全事件数据');
  return cleaned
    .split('\n')
    .filter((line) => {
      const trimmed = line.trim();
      if (!trimmed) {
        return true;
      }
      return !/^(system prompt|hidden prompt|developer prompt|internal prompt|prompt text|hidden policy|tool gateway|prompt injection|raw tool|tool result|tool results)\b/i.test(trimmed)
        && !/^(提示词|系统提示词|隐藏策略|工具网关|内部流程|执行过程|原始工具|工具结果|提示词注入)(?:\s|：|:|，|,|。|$)/.test(trimmed);
    })
    .join('\n')
    .trim();
}

export function safeAssistantDisplayText(value?: string) {
  return stripInternalProcessPhrases(String(value ?? '')).replace(/\s+/g, ' ').trim();
}

function normalizeMarkdownForAssistant(value: string) {
  return value
    .replace(/\r\n/g, '\n')
    .replace(/([：:])\s*(\|\s*[^|\n]+?\s*\|[^|\n]+?\|)/g, '$1\n$2')
    .replace(/\|\s*\|(?=\s*[:\-\w\u3400-\u9fff])/g, '|\n|')
    .split('\n')
    .flatMap(splitInlineMarkdownTable)
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function splitInlineMarkdownTable(line: string) {
  const tableStart = findInlineTableStart(line);
  if (tableStart <= 0) {
    return [line];
  }
  const prefix = line.slice(0, tableStart).trim();
  const table = line.slice(tableStart).trim();
  return prefix ? [prefix, table] : [table];
}

function findInlineTableStart(line: string) {
  for (let index = 0; index < line.length; index += 1) {
    if (line[index] !== '|') {
      continue;
    }
    const rest = line.slice(index);
    const pipeCount = (rest.match(/\|/g) ?? []).length;
    if (pipeCount >= 4) {
      return index;
    }
  }
  return -1;
}

function isMarkdownTableStart(lines: string[], index: number) {
  return isTableRow(lines[index]) && index + 1 < lines.length && /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(lines[index + 1]);
}

function isTableRow(line: string) {
  return /^\s*\|.+\|\s*$/.test(line);
}

function parseTableRow(line: string) {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((cell) => cell.trim());
}

function renderInlineMarkdown(text: string) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean);
  return parts.map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={`${part}-${index}`}>{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={`${part}-${index}`}>{part.slice(2, -2)}</strong>;
    }
    return <span key={`${part}-${index}`}>{part}</span>;
  });
}
