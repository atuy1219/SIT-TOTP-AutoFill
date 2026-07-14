# SIT TOTP AutoFill

芝浦工業大学のADFSログインで、大学アカウントの入力、Azure MFAプロバイダーの選択、SHA-256 TOTPの入力を補助するChrome Manifest V3拡張機能です。

## 必要環境

- Node.js 18以上
- npm（Node.jsに同梱）

外部npmパッケージは使用しません。`npm install` は不要です。

## 検証

```bash
npm run check
```

`manifest.json`、参照ファイル、JavaScript構文を検証します。

## ビルド

```bash
npm run build
```

`dist/` にChromeへ読み込める拡張機能を生成します。

Chromeで確認する場合は、`chrome://extensions/` を開き、デベロッパーモードを有効にして「パッケージ化されていない拡張機能を読み込む」から `dist/` を指定します。

## 配布用ZIPの生成

```bash
npm run package
```

`release/sit-adfs-totp-autofill-chrome-mv3-v0.3.1.zip` を生成します。ZIP内のルートに `manifest.json` が配置されるため、そのまま配布用として利用できます。

## セキュリティ上の注意

TOTPシードと大学アカウント情報は、マスターパスワードからPBKDF2-SHA256で導出した鍵を使用し、AES-GCMで暗号化してChromeのローカルストレージに保存します。マスターパスワード、TOTPシード、大学アカウント情報をソースコードやIssueへ記載しないでください。

## ツールの使用方法

root化済みAndroid等からPhoneFactorを抜き出し、`extract_phonefactor_seed.py`と同じ場所に置いてください。
スクリプトの実行後、`oath_secret_key`をコピーします。これがシードです。
その後、`generate_totp.py`を実行し、Seed:が出たら、キーを入力してください。
