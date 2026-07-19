# SIT TOTP AutoFill

芝浦工業大学のADFSログインで、大学アカウントの入力、Azure MFAプロバイダーの選択、SHA-256 TOTPの入力を補助するChromium（Chrome・Edgeなど）およびFirefox向け拡張機能です。

## 使用方法

### 1. Microsoftアカウントのサインイン方法を変更する

1. [セキュリティ情報](https://mysignins.microsoft.com/security-info)にアクセスします。
2. 「最も適したものが利用できない場合のサインイン方法」を、`Authenticator アプリまたはハードウェア トークン - コード` に変更します。

### 2. Microsoft Authenticatorを登録する

root化済みのAndroid端末、またはrootを利用できるAndroid EmulatorにMicrosoft Authenticatorをインストールし、大学アカウントを登録します。

Android EmulatorではQRコードを読み取れないため、登録画面で `Can't scan the QR code?` を選択し、表示された情報をテキストで入力してください。

### 3. Pythonをインストールする

Pythonがインストールされていない場合はPython 3をインストールします。

Windowsでは、PowerShellまたはコマンドプロンプトからwingetを使用できます。

```powershell
winget install --id Python.Python -e
```

インストール後、次のコマンドでPythonが利用できることを確認してください。

```bash
python --version
```

### 4. TOTPシードを取り出す

Microsoft Authenticatorのデータベース `PhoneFactor`、`PhoneFactor-wal`、`PhoneFactor-shm`を、`tools/extract_phonefactor_seed.py` と同じディレクトリに配置します。

Android上の保存場所は次のとおりです。

```text
/data/user/0/com.azure.authenticator/databases/PhoneFactor
```

リポジトリのルートディレクトリで、次のコマンドを実行します。

```bash
python tools/extract_phonefactor_seed.py
```

出力された `oath_secret_key` のうち、自分の大学アカウントに対応する32文字の英数字がTOTPシードです。

> [!CAUTION]
> TOTPシードは認証コードを生成できる秘密情報です。第三者への送信、画面共有、Issueへの投稿、ソースコードへの記載など、外部への公開は絶対にしないでください。

### 5. 拡張機能を設定する

1. 使用するブラウザー向けの拡張機能をインストールします。ソースコードから利用する場合は、後述の「ビルド」を参照してください。
2. 拡張機能の設定画面を開きます。
3. 先ほど取り出したTOTPシードを入力します。
4. 必要な自動化項目を選択して保存します。

#### 学籍番号とパスワードを保存しない場合

「IDとパスワードを入力して自動送信する」を無効にしてください。大学ユーザー名と大学アカウントのパスワードは空欄のまま設定でき、TOTP入力などの機能だけを利用できます。

#### マスターパスワードを使用しない場合

初期設定で「マスターパスワードで保護する（推奨）」を無効にしてください。ブラウザを再起動してもマスターパスワードの入力なしで自動入力できます。

> [!WARNING]
> このモードでは、自動解除キーをブラウザーのローカルストレージに保存します。保存データ自体はAES-GCMで暗号化されますが、同じブラウザープロファイルを操作できる第三者に対する保護にはなりません。共有PCでは使用しないでください。

保護方式を変更する場合は、設定画面の「すべて削除」を実行して初期設定をやり直してください。

以上で設定は完了です。

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

Chromium版とFirefox版をまとめて生成します。

```bash
npm run build
```

生成先は次のとおりです。

```text
dist/chromium/  Chrome、EdgeなどのChromium系ブラウザー向け
dist/firefox/   Firefox向け
```

個別に生成する場合は、次のコマンドを使用します。

```bash
npm run build:chromium
npm run build:firefox
```

Chromium版は、ChromeまたはEdgeの拡張機能管理画面でデベロッパーモードを有効にし、「パッケージ化されていない拡張機能を読み込む」から `dist/chromium/` を指定します。

Firefox版は `about:debugging#/runtime/this-firefox` を開き、「一時的なアドオンを読み込む」から `dist/firefox/manifest.json` を指定します。

Firefox版では、ビルド時にバックグラウンド処理をFirefox向けに変換し、WebExtensions APIの名前空間を `browser` に置き換えます。ChromeとEdgeは同じChromium版を使用します。

## 配布用ZIPの生成

```bash
npm run package
```

`release/` に次の配布ファイルを生成します。

```text
sit-adfs-totp-autofill-chromium-v<version>.zip
sit-adfs-totp-autofill-firefox-v<version>.zip
```

## GitHub Actions

`Build extension` ワークフローは、Chromium版とFirefox版を別々のartifactとしてアップロードします。artifactには展開済みの拡張機能ファイルを直接格納するため、ダウンロードしたZIPを一度展開すれば利用できます。

`Publish release` ワークフローは手動実行専用です。タグを空欄にするとManifestのバージョンから `v<version>` を使用し、Chromium版とFirefox版の配布ZIPをGitHub Releaseへアップロードします。同じタグのReleaseが既に存在する場合は、既存のファイルを置き換えます。

## セキュリティ上の注意

マスターパスワードを使用する場合、TOTPシードと大学アカウント情報は、PBKDF2-SHA256で導出した鍵を使用し、AES-GCMで暗号化してブラウザーのローカルストレージに保存します。

マスターパスワードを使用しない場合もAES-GCMで暗号化しますが、自動解除キーを同じブラウザープロファイル内に保存するため、端末やブラウザープロファイルを操作できる第三者への防御にはなりません。

マスターパスワード、TOTPシード、大学アカウント情報をソースコードやIssueへ記載しないでください。

## 注意事項

この拡張機能は私の研究目的で作成したもので、芝浦工業大学、Microsoftとは一切の関係がありません。

大学側、Microsoftの仕様変更で突然利用できなくなる可能性があります。
