import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

// Local only. Never prints key values; refuses to replace existing keys.
const target=resolve(process.cwd(),'.keys');
await mkdir(target,{recursive:true,mode:0o700});
await writeFile(resolve(target,'ADMIN_API_KEY.txt'),randomBytes(32).toString('base64url')+'\n',{flag:'wx',mode:0o600});
await writeFile(resolve(target,'ENCRYPTION_KEY_B64.txt'),randomBytes(32).toString('base64')+'\n',{flag:'wx',mode:0o600});
console.log('Independent keys saved locally in ignored .keys/. No values were printed.');
