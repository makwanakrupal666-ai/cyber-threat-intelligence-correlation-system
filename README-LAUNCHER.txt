CTI CORE ONE-CLICK LAUNCHER

What it does
- Starts the FastAPI backend in a separate terminal window if /health is not already responding.
- Starts the Vite frontend in a separate terminal window if port 5173 is not already responding.
- Opens http://localhost:5173 in your browser.
- Leaves server windows open so you can see errors and stop the servers when done.

Install
1. Copy/extract these files into the EXISTING project root:
   D:\Project\cti-project-final
   The same folder should contain backend, frontend, .venv and this launcher.
2. Double-click Install-CTI-CORE-Desktop-Shortcut.bat once.
3. A desktop shortcut named "CTI CORE" will be created.
4. From then on, double-click the CTI CORE desktop shortcut.

Important
- Do not extract this package over/replace the whole project.
- Do not move the launcher away from the project root after installing the shortcut.
- Keep the Backend and Frontend terminal windows open while using the dashboard.
- Close those server windows when you finish.
- The script does not install packages or change/delete MongoDB data.
- If frontend/node_modules is missing, open a terminal in frontend and run npm ci once.
