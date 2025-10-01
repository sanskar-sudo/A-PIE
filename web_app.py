from flask import Flask, jsonify, request, send_from_directory, Response
from werkzeug.utils import secure_filename
import os
from utils.core import (
    check_api,
    analyze_uploaded_pe_bytes,
    write_report,
    stream_analyze_uploaded_pe_bytes,
    fetch_api_descriptions,
)


app = Flask(__name__, static_folder="web/static", template_folder="web")


@app.route("/api/lookup", methods=["POST"])
def api_lookup():
    data = request.get_json(silent=True) or {}
    api_field = data.get("api")
    if not api_field:
        return jsonify({"error": "Missing 'api' name(s)"}), 400

    # Support string with commas/spaces or array of strings
    names = []
    if isinstance(api_field, list):
        for item in api_field:
            if isinstance(item, str):
                names.extend([t for t in item.replace("\n", " ").replace("\t", " ").replace(",", " ").split() if t])
    elif isinstance(api_field, str):
        names = [t for t in api_field.replace("\n", " ").replace("\t", " ").replace(",", " ").split() if t]
    else:
        return jsonify({"error": "Invalid 'api' format; provide string or array of strings"}), 400

    if not names:
        return jsonify({"results": {}})

    try:
        # Use existing parallel fetcher
        result = fetch_api_descriptions(names, verbose=False)
        return jsonify({"results": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    verbose = request.args.get("verbose", "false").lower() == "true"
    do_export = request.args.get("export", "false").lower() == "true"
    stream = request.args.get("stream", "false").lower() == "true"

    if "file" not in request.files:
        return jsonify({"error": "No file provided. Use multipart/form-data with 'file' field."}), 400
    file = request.files["file"]
    filename = secure_filename(file.filename or "uploaded.bin")
    data = file.read()
    if not data:
        return jsonify({"error": "Empty file."}), 400

    if stream and verbose:
        def generate():
            for chunk in stream_analyze_uploaded_pe_bytes(data, verbose=True):
                yield chunk
        return Response(generate(), mimetype="text/event-stream")

    try:
        results = analyze_uploaded_pe_bytes(data, verbose=verbose)
        export_path = None
        if do_export:
            export_path = write_report(results, sample_name=filename)
        return jsonify({"results": results, "export_path": export_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def index():
    return send_from_directory(app.template_folder, "index.html")


@app.route("/static/<path:path>")
def static_proxy(path):
    return send_from_directory(app.static_folder, path)


@app.route("/pie.png")
def serve_pie_logo():
    # Serve the pie image from project root if present
    root_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(root_dir, "pie.png")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)


