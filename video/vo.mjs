// Voiceover: one mp3 per scene via edge-tts (free Microsoft neural voices, no key). `npm run vo`, then re-render.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
const { voice, rate, lines } = JSON.parse(readFileSync(new URL("./vo.json", import.meta.url)));
for (const [scene, text] of Object.entries(lines)) {
  const out = new URL(`./public/vo/${scene}.mp3`, import.meta.url).pathname;
  execFileSync("uvx", ["edge-tts", "--voice", voice, "--rate", rate, "--text", text, "--write-media", out], { stdio: "inherit" });
  const secs = execFileSync("afinfo", [out]).toString().match(/estimated duration: ([\d.]+)/)?.[1];
  console.log(`${scene.padEnd(8)} ${secs} s`);
}
