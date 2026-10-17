"use strict";

const requestId = new URL(location.href).searchParams.get("id");
const confirmButton = document.getElementById("confirmButton");
const cancelButton = document.getElementById("cancelButton");
const statusMessage = document.getElementById("message");
let requestOptions;

PasskeyClient.send("passkeyGetRequest", { id: requestId }).then(options => {
  requestOptions = options;
  confirmButton.disabled = false;
}).catch(() => {
  statusMessage.textContent = "確認を開始できません。元のタブで通常のログインを利用してください。";
});

async function closeConfirmation() {
  const tab = await chrome.tabs.getCurrent();
  await chrome.tabs.remove(tab.id);
}

confirmButton.addEventListener("click", async () => {
  confirmButton.disabled = true;
  cancelButton.disabled = true;
  try {
    await PasskeyClient.authenticate(requestOptions);
    statusMessage.textContent = "確認しました。元のタブでログインを続けます。";
    await closeConfirmation();
  } catch (error) {
    await PasskeyClient.send("passkeyCancel", { id: requestId }).catch(() => {});
    statusMessage.textContent = (error.name === "NotAllowedError" ? "確認をキャンセルしました。" : error.message) +
      " 元のタブで通常のログインを利用できます。";
    cancelButton.disabled = false;
  }
});

cancelButton.addEventListener("click", async () => {
  await PasskeyClient.send("passkeyCancel", { id: requestId }).catch(() => {});
  await closeConfirmation();
});
