# ScombZ Login Helper

芝浦工業大学の **ScombZへの自動ログインとSESSION更新** を補助する、Chromium（Chrome・Edge）/ Firefox向け拡張機能です。ScombApp Mobile API（Bearer Token → OTKEY）でWeb SESSIONを取得するため、ScombZログインにTOTPは不要です。

従来のADFS自動ログイン・SHA-256 TOTP生成機能も利用できますが、初期状態では無効です。詳細な使い方は下部の折りたたみ欄を参照してください。

> [!NOTE]
> 芝浦工業大学・Microsoftの公式製品ではありません。PR #5がマージされるまで拡張機能のバージョンを **0.7.0** に固定します。既存データの互換性のため、保存領域のキーやバックアップ形式の識別子は変更しません。

## 使い方：ScombZ自動ログイン

1. 拡張機能をブラウザーに読み込み、設定を開きます。
2. 大学ユーザー名と大学パスワードを入力し、保存します（初期設定では必須）。
3. 「ScombZ自動ログイン」の **APIに接続** を押します。接続後はBearer Tokenが暗号化保管庫に保存されます。**チェックボックス類は変更した瞬間に自動保存**されます。大学ユーザー名・パスワードは「大学アカウントを保存」、TOTPシードは「TOTPシードを保存」で、それぞれ個別に登録します。
4. 通常どおり [ScombZ](https://scombz.shibaura-it.ac.jp/portal/home) にアクセスします。セッションが切れた場合は自動復旧を試みます。

ScombZを開く専用ボタンはありません。認証経路は大学のMobile APIとOTKEYブリッジを利用します。OTKEYやSESSION Cookieを手動生成するものではありません。

### ログイン画面の表示を回避（試験機能）

設定画面で **「/login画面の表示を回避（試験機能）」** をオンにできます。**初期状態はオフ**で、従来の動作を維持します。

- **オフ（既存の安定動作）**：大学側が未認証と判断した際にログイン画面への遷移を検出して、OTKEY認証で復旧します。
- **オン（試験機能）**：ブラウザーの declarativeNetRequest でScombZのログイン画面への移動要求を、拡張機能内の**表示内容がない認証用ページ**へ振り替えます。「セッションを更新しています」などの文言は通常表示せず、OTKEY取得後はホームへ遷移します。API認証できなければ迂回を解除して通常の大学ログイン画面へ戻します。認証が長時間停止した場合だけ手動切り替え操作を表示します。

この機能で**大学サーバーからのログイン要求そのものはなくなりません**。大学側のログイン画面をブラウザーに表示する前に迂回します。明示的なログアウトを優先し、ログアウト直後の強制再ログインはしません。試験機能は大学サイトの実機検証がまだ必要です。

### SESSION復旧の仕組み

1. ScombZが未認証と判定してログイン画面へリダイレクトすると、拡張機能はOTKEYを先行取得します。
2. 既存動作ではログイン画面の遷移確定後（リロード時は読み込み完了時も再試行）、試験機能では拡張機能の「認証中」画面から、OTKEYのブリッジ先へ移動します。
3. Mobile APIのOTKEYを使い、モバイル用ホストの「OTKEY / portal/home」経路で大学サーバーから新しいSESSION Cookieを受け取ります。
4. セッション確立後、リダイレクト前の元URLが記録されていれば、**元のGETページへ復帰します**。直接 `/login` を開いた場合は記録された復帰先がないためホームに留まります。POSTフォームの再送信やSPA内の画面状態の復元はしません。

リダイレクト中に勝手にタブのURLを差し替える処理は行いません。重複認証・リダイレクトループを制限します。

## 認証情報・バックアップ

大学パスワード、Bearer Token、TOTPシードはAES-GCMで暗号化してブラウザー内に保存されます。ただし解除キーも同じブラウザープロファイルに保存するため、そのプロファイル自体を操作できる第三者への保護は限定的です。

**大学パスワード・APIトークンはバックアップに含めません。ファイルは暗号化されていないので安全な場所に保管してください。** バックアップには大学ユーザー名・設定・TOTPシードが含まれ、TOTPシードは平文です。復元後は大学パスワードとScombApp API接続を再設定します。

## レガシー機能：ADFS・TOTP

<details>
<summary>Microsoft 365向けADFSの自動入力、TOTPシード抽出、コード生成の手順を表示</summary>

ADFSのID・パスワード自動入力、MFA選択、TOTP自動入力は初期状態ではオフです。必要な場合だけ設定画面の**「レガシー機能」**を展開してください。TOTPシードの保存は個別ボタン、ADFSのチェックボックスは変更時に自動保存されます。

#### 1. Microsoftアカウントのサインイン方法を変更する

1. [セキュリティ情報](https://mysignins.microsoft.com/security-info)にアクセスします。
2. 「最も適したものが利用できない場合のサインイン方法」を、`Authenticator アプリまたはハードウェア トークン - コード` に変更します。

#### 2. Microsoft Authenticatorを登録する

root化済みのAndroid端末、またはrootを利用できるAndroid EmulatorにMicrosoft Authenticatorをインストールし、大学アカウントを登録します。

Android EmulatorではQRコードを読み取れないため、登録画面で `Can't scan the QR code?` を選択し、表示された情報をテキストで入力してください。

#### 3. Pythonをインストールする

Pythonがインストールされていない場合はPython 3をインストールします。

Windowsでは、PowerShellまたはコマンドプロンプトからwingetを使用できます。

```powershell
winget install --id Python.Python -e
```

インストール後、次のコマンドでPythonが利用できることを確認してください。

```bash
python --version
```

#### 4. TOTPシードを取り出す

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

#### 5. 拡張機能を設定する

1. 使用するブラウザー向けの拡張機能をインストールします。ソースコードから利用する場合は、後述の「ビルド」を参照してください。
2. 拡張機能の設定画面を開きます。
3. TOTPコードを使う場合はシードを入力します（ScombZのみ使う場合は省略可能）。
4. 初期設定を保存します。初期設定後はレガシー設定の各チェックボックスは自動保存されます。TOTPシードは専用の保存ボタンから更新できます。初期設定時にシードを登録した場合だけコード確認画面が表示されます。

#### レガシー機能を有効にする場合

初期設定および設定画面で「レガシー：TOTPシード・コード表示」と「レガシー：ADFS自動ログイン・TOTP自動入力」を開いて必要な項目だけ設定します。通常は折りたたまれた状態です。TOTPシードの有無にかかわらず大学アカウントのパスワードは必須です。

### 画面変更の診断

ADFSページで既知のログイン画面、MFA選択画面、TOTP入力画面のいずれも認識できない状態が4秒以上続くと、画面右下に診断パネルを表示します。

「診断情報をコピー」を押すと、拡張機能のバージョン、URLのパス、検出した要素IDなどをコピーできます。入力値、TOTPシード、大学パスワード、URLのクエリ文字列は含みません。
</details>

## トラブルシューティング

- **API接続できない**：大学ユーザー名・大学パスワードを確認して「APIに接続」を実行してください。
- **ScombZログイン画面から戻れない**：試験機能を無効にし、通常の復旧方式でログイン画面を再読み込みしてください。
- **旧版のエラーが残る**：拡張機能の管理画面から最新版を再読み込みしてください。
- Issue等にパスワード、Bearer Token、OTKEY、SESSION、TOTPシードを投稿しないでください。

## 必要環境

- Node.js 18以上
- npm（Node.jsに同梱）

外部npmパッケージは使用しません。`npm install` は不要です。

## 検証

```bash
npm run check
```

`manifest.json`、参照ファイル、JavaScript構文を検証し、ScombZ API接続・OTKEY転送の回帰テストを実行します。

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
scombz-login-helper-chromium.zip
scombz-login-helper-firefox.zip
```

## GitHub Actions

`Build extension` ワークフローは、Chromium版とFirefox版を別々のartifactとしてアップロードします。artifactには展開済みの拡張機能ファイルを直接格納するため、ダウンロードしたZIPを一度展開すれば利用できます。

`Publish release` ワークフローは手動実行専用です。タグを空欄にするとManifestのバージョンから `v<version>` を使用し、Chromium版とFirefox版の配布ZIPをGitHub Releaseへアップロードします。同じタグのReleaseが既に存在する場合は、既存のファイルを置き換えます。

## セキュリティ上の注意

端末のランダムなキーとAES-GCMでTOTPシード、大学アカウント情報、Mobile API Bearer Tokenを暗号化してブラウザーのローカルストレージに保存します。自動解除キーもブラウザープロファイル内にあるため、そのプロファイルを操作できる第三者への保護にはなりません。

平文バックアップ内のTOTPシード、大学パスワード、Bearer Tokenをソースコード・Issue・ログへ記載しないでください。

## 注意事項

この拡張機能は私の研究目的で作成したもので、芝浦工業大学、Microsoftとは一切の関係がありません。

大学側、Microsoftの仕様変更で突然利用できなくなる可能性があります。
