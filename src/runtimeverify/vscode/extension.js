const vscode = require('vscode');
const http = require('http');

/**
 * VS Code Extension entry point for verify monitoring panel.
 * Connects to the local FastAPI verify REST API to fetch live sessions and decisions.
 */
function activate(context) {
    console.log('verify AI Runtime Verification extension is active.');

    // Register inspection command
    let inspectCmd = vscode.commands.registerCommand('verify.inspectSession', async () => {
        const sessionId = await vscode.window.showInputBox({
            prompt: 'Enter the session ID to inspect',
            placeHolder: 'e.g. session_123'
        });

        if (sessionId) {
            fetchSessionDetails(sessionId);
        }
    });

    // Register doctor command
    let doctorCmd = vscode.commands.registerCommand('verify.runDoctor', () => {
        vscode.window.showInformationMessage('verify: Running doctor check...');
    });

    context.subscriptions.push(inspectCmd);
    context.subscriptions.push(doctorCmd);
}

function fetchSessionDetails(sessionId) {
    const config = vscode.workspace.getConfiguration('verify');
    const apiUrl = config.get('apiUrl') || 'http://127.0.0.1:8000';

    http.get(`${apiUrl}/session/${sessionId}`, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => {
            try {
                const history = JSON.parse(data);
                vscode.window.showInformationMessage(`verify: Fetched ${history.length} session transitions.`);
            } catch (e) {
                vscode.window.showErrorMessage(`verify: Failed to parse session data: ${e.message}`);
            }
        });
    }).on('error', (err) => {
        vscode.window.showErrorMessage(`verify: Failed to connect to verify API: ${err.message}`);
    });
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
