/* PrintCard design editor — built on Fabric.js 5.x (static/js/vendor/fabric.min.js).
 *
 * The template SVG is split in two: its <text> nodes become editable fabric.IText
 * objects, everything else becomes the (locked) canvas background. Only the text
 * objects are saved (CUSTOM_DESIGN.content); the PNG export goes to imageUrl.
 */
(() => {
  const root = document.getElementById("design-editor");
  if (!root) return;
  const canvasElement = document.getElementById("canvas");
  const wrap = canvasElement.parentElement;
  const textInput = document.getElementById("element-text");
  const fontSelect = document.getElementById("font-family");
  const sizeInput = document.getElementById("font-size");
  const colorInput = document.getElementById("font-color");
  const message = document.getElementById("editor-message");

  if (!window.fabric) {
    message.textContent = "Không tải được trình chỉnh sửa. Vui lòng tải lại trang.";
    return;
  }

  const MAX_OBJECTS = 30;
  const FONTS = ["Arial", "Georgia", "Times New Roman", "Verdana", "Tahoma", "Trebuchet MS", "Courier New"];
  const ACCENT = "#b49458";

  let savedObjects = [];
  let template = {};
  try { savedObjects = JSON.parse(root.dataset.elements || "[]"); } catch { savedObjects = []; }
  try { template = JSON.parse(root.dataset.template || "{}"); } catch { template = {}; }
  let savedCanvas = null;
  try { savedCanvas = JSON.parse(root.dataset.canvas || "null"); } catch { savedCanvas = null; }

  const canvas = new fabric.Canvas(canvasElement, {
    preserveObjectStacking: true,
    selection: false,
    enableRetinaScaling: false,
    backgroundColor: "#fffefa",
  });

  // ---- canvas size ---------------------------------------------------------
  function setSizeFromTemplate() {
    const size = typeof template.size === "string" ? template.size : "";
    const mm = size.match(/^(\d+(?:\.\d+)?)x(\d+(?:\.\d+)?)mm$/i);
    if (mm) canvas.setDimensions({ width: 900, height: Math.round(900 * Number(mm[2]) / Number(mm[1])) });
    else if (/^A5$/i.test(size)) canvas.setDimensions({ width: 900, height: Math.round(900 * 148 / 210) });
  }

  // Keep the backing store at design size; only the CSS size follows the page width.
  function fit() {
    const style = getComputedStyle(wrap);
    const available = wrap.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    if (!(available > 0)) return;
    const cssWidth = Math.min(available, canvas.getWidth());
    const scale = cssWidth / canvas.getWidth();
    // cssOnly values must carry a unit: fabric writes them straight into element.style,
    // and a bare number is ignored by the browser (the canvas then stays 900px wide and gets clipped).
    canvas.setDimensions({ width: cssWidth + "px", height: (canvas.getHeight() * scale) + "px" }, { cssOnly: true });
    canvas.calcOffset();
  }
  window.addEventListener("resize", fit);
  // Also refit when the layout changes without a window resize (scrollbar, fonts, sidebar wrapping).
  if (window.ResizeObserver) {
    let lastWidth = 0;
    new ResizeObserver(() => {
      if (Math.abs(wrap.clientWidth - lastWidth) < 1) return;
      lastWidth = wrap.clientWidth;
      fit();
    }).observe(wrap);
  }

  // ---- text objects --------------------------------------------------------
  const round = (value, digits = 1) => Math.round(value * 10 ** digits) / 10 ** digits;

  function textSpec(spec) {
    return {
      text: String(spec.text),
      left: spec.left, top: spec.top,
      originX: spec.originX || "left", originY: spec.originY || "top",
      fontSize: spec.fontSize || 32, fill: spec.fill || "#20242a",
      fontFamily: FONTS.includes(spec.fontFamily) ? spec.fontFamily : "Arial",
      fontWeight: spec.fontWeight === "bold" ? "bold" : "normal",
      fontStyle: spec.fontStyle === "italic" ? "italic" : "normal",
      textAlign: spec.textAlign || "left",
      angle: spec.angle || 0, scaleX: spec.scaleX || 1, scaleY: spec.scaleY || 1,
      charSpacing: spec.charSpacing || 0,
    };
  }

  function makeText(spec) {
    const clean = textSpec(spec);
    const object = new fabric.IText(clean.text, {
      ...clean,
      cornerColor: ACCENT, borderColor: ACCENT, cornerStyle: "circle",
      cornerSize: 10, transparentCorners: false, padding: 4,
      lockUniScaling: true,
    });
    object.setControlsVisibility({ mt: false, mb: false, ml: false, mr: false });
    return object;
  }

  // Positions saved by the first editor version were normalised (0-1) and baseline-less.
  function fromLegacy(element) {
    const family = { serif: "Georgia", mono: "Courier New" }[element.family] || "Arial";
    const align = element.align || "left";
    return {
      text: element.text,
      left: element.x * canvas.getWidth(), top: element.y * canvas.getHeight(),
      originX: align, originY: "center", textAlign: align,
      fontSize: element.font_size, fill: element.color, fontFamily: family,
      fontWeight: element.bold ? "bold" : "normal", fontStyle: element.italic ? "italic" : "normal",
      charSpacing: element.spacing ? (element.spacing / element.font_size) * 1000 : 0,
    };
  }

  const texts = () => canvas.getObjects().filter(object => object.type === "i-text");
  const activeText = () => {
    const object = canvas.getActiveObject();
    return object && object.type === "i-text" ? object : null;
  };

  function snapshot() {
    return texts().filter(object => object.text && object.text.trim()).map(object => ({
      text: object.text,
      left: round(object.left), top: round(object.top),
      originX: object.originX, originY: object.originY,
      fontSize: round(object.fontSize), fill: object.fill,
      fontFamily: object.fontFamily,
      fontWeight: object.fontWeight === "bold" || Number(object.fontWeight) >= 600 ? "bold" : "normal",
      fontStyle: object.fontStyle === "italic" ? "italic" : "normal",
      textAlign: object.textAlign,
      angle: round(((object.angle % 360) + 360) % 360),
      scaleX: round(object.scaleX, 3), scaleY: round(object.scaleY, 3),
      charSpacing: Math.round(object.charSpacing || 0),
    }));
  }

  // ---- history (Fabric has no built-in undo) ------------------------------
  let history = [];
  let restoring = false;
  let timer = null;

  function record() {
    if (restoring) return;
    const state = JSON.stringify(snapshot());
    if (history[history.length - 1] === state) return;
    history.push(state);
    if (history.length > 50) history.shift();
  }
  function scheduleRecord() {
    if (restoring) return;
    clearTimeout(timer);
    timer = setTimeout(record, 300);
  }
  function restore(specs) {
    restoring = true;
    canvas.discardActiveObject();
    texts().forEach(object => canvas.remove(object));
    specs.forEach(spec => canvas.add(makeText(spec)));
    restoring = false;
    canvas.requestRenderAll();
    syncPanel();
  }
  function undo() {
    clearTimeout(timer);
    record();
    if (history.length < 2) return;
    history.pop();
    restore(JSON.parse(history[history.length - 1]));
  }

  // ---- side panel ----------------------------------------------------------
  function syncPanel() {
    const object = activeText();
    if (!object) { textInput.value = ""; return; }
    textInput.value = object.text;
    fontSelect.value = FONTS.includes(object.fontFamily) ? object.fontFamily : "Arial";
    sizeInput.value = Math.round(object.fontSize * (object.scaleY || 1));
    if (/^#[0-9a-f]{6}$/i.test(object.fill)) colorInput.value = object.fill;
  }

  function change(properties) {
    const object = activeText();
    if (!object) return;
    object.set(properties);
    object.setCoords();
    canvas.requestRenderAll();
    scheduleRecord();
  }

  // Bake any resize handle scaling into the font size so the panel stays truthful.
  function bakeScale(object) {
    if (object.scaleX === 1 && object.scaleY === 1) return;
    object.set({ fontSize: round(object.fontSize * object.scaleY), scaleX: 1, scaleY: 1 });
    object.setCoords();
  }

  canvas.on("selection:created", syncPanel);
  canvas.on("selection:updated", syncPanel);
  canvas.on("selection:cleared", syncPanel);
  canvas.on("object:modified", event => {
    if (event.target && event.target.type === "i-text") { bakeScale(event.target); syncPanel(); }
    scheduleRecord();
  });
  canvas.on("text:changed", event => {
    if (event.target === activeText()) textInput.value = event.target.text;
    scheduleRecord();
  });
  canvas.on("text:editing:exited", event => {
    const object = event.target;
    if (object && !object.text.trim()) canvas.remove(object);
    syncPanel();
    scheduleRecord();
  });
  canvas.on("object:removed", scheduleRecord);

  textInput.addEventListener("input", () => {
    const object = activeText();
    if (object) change({ text: textInput.value.slice(0, 500) || " " });
  });
  fontSelect.addEventListener("change", () => change({ fontFamily: fontSelect.value }));
  sizeInput.addEventListener("input", () => {
    const value = Number(sizeInput.value);
    if (value >= 8 && value <= 200) change({ fontSize: value, scaleX: 1, scaleY: 1 });
  });
  colorInput.addEventListener("input", () => change({ fill: colorInput.value }));
  document.getElementById("toggle-bold").addEventListener("click", () => {
    const object = activeText();
    if (object) change({ fontWeight: object.fontWeight === "bold" ? "normal" : "bold" });
  });
  document.getElementById("toggle-italic").addEventListener("click", () => {
    const object = activeText();
    if (object) change({ fontStyle: object.fontStyle === "italic" ? "normal" : "italic" });
  });
  // Alignment is relative to the page: snap the text to the left margin, centre or right margin.
  function alignOnPage(side) {
    const object = activeText();
    if (!object) return;
    const margin = canvas.getWidth() * 0.06;
    const left = side === "left" ? margin : side === "right" ? canvas.getWidth() - margin : canvas.getWidth() / 2;
    change({ originX: side, textAlign: side, left });
  }
  document.getElementById("align-left").addEventListener("click", () => alignOnPage("left"));
  document.getElementById("align-center").addEventListener("click", () => alignOnPage("center"));
  document.getElementById("align-right").addEventListener("click", () => alignOnPage("right"));

  document.getElementById("add-text").addEventListener("click", () => {
    if (texts().length >= MAX_OBJECTS) { message.textContent = `Tối đa ${MAX_OBJECTS} đối tượng chữ.`; return; }
    const object = makeText({
      text: textInput.value.trim().slice(0, 500) || "Nhập nội dung",
      left: canvas.getWidth() / 2, top: canvas.getHeight() / 2,
      originX: "center", originY: "center", textAlign: "center",
      fontSize: Number(sizeInput.value) || 32, fill: colorInput.value, fontFamily: fontSelect.value,
    });
    message.textContent = "";
    canvas.add(object);
    canvas.setActiveObject(object);
    canvas.requestRenderAll();
    scheduleRecord();
  });
  document.getElementById("delete-text").addEventListener("click", () => {
    const object = activeText();
    if (!object) return;
    canvas.discardActiveObject();
    canvas.remove(object);
    canvas.requestRenderAll();
  });
  document.getElementById("undo").addEventListener("click", undo);
  document.addEventListener("keydown", event => {
    const object = activeText();
    if (event.key === "Delete" && object && !object.isEditing && document.activeElement === document.body) {
      canvas.discardActiveObject();
      canvas.remove(object);
      canvas.requestRenderAll();
    } else if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "z"
               && !(object && object.isEditing) && document.activeElement === document.body) {
      event.preventDefault();
      undo();
    }
  });

  // ---- template background -------------------------------------------------
  // ---- SVG template parsing ------------------------------------------------
  // The template SVG is split in two: text it can express as an editable object is
  // lifted out; anything it cannot express stays in the background so nothing is lost.
  const colorProbe = document.createElement("canvas").getContext("2d");
  const SKIPPED_PARENTS = "defs, clipPath, mask, symbol, pattern, marker";
  let svgRules = {};

  function declarations(body) {
    const out = {};
    String(body || "").split(";").forEach(part => {
      const index = part.indexOf(":");
      if (index > 0) out[part.slice(0, index).trim().toLowerCase()] = part.slice(index + 1).trim();
    });
    return out;
  }

  // Simple ".class{...}" and "text{...}" rules from <style> blocks.
  function readStyleRules(svg) {
    const rules = {};
    svg.querySelectorAll("style").forEach(style => {
      for (const [, selectors, body] of style.textContent.matchAll(/([^{}]+)\{([^}]*)\}/g)) {
        selectors.split(",").map(selector => selector.trim()).filter(selector => /^(\.[\w-]+|text|tspan)$/.test(selector))
          .forEach(selector => { rules[selector] = { ...(rules[selector] || {}), ...declarations(body) }; });
      }
    });
    return rules;
  }

  function styleOf(element) {
    const out = { ...(svgRules[element.nodeName.toLowerCase()] || {}) };
    (element.getAttribute("class") || "").split(/\s+/).forEach(name => Object.assign(out, svgRules["." + name] || {}));
    return Object.assign(out, declarations(element.getAttribute("style")));
  }

  // A presentation property from the node itself or the closest ancestor that sets it.
  function inherited(node, name) {
    for (let element = node; element && element.nodeType === 1; element = element.parentNode) {
      const value = styleOf(element)[name] || element.getAttribute(name);
      if (value) return value.trim();
    }
    return "";
  }

  function svgColor(value, doc) {
    const reference = value.match(/^url\(\s*#([^)\s]+)\s*\)/);
    if (reference) {
      const stops = doc.getElementById(reference[1])?.querySelectorAll("stop") || [];
      const stop = stops[Math.floor(stops.length / 2)];
      value = stop ? (styleOf(stop)["stop-color"] || stop.getAttribute("stop-color") || "") : "";
    }
    if (!value || value === "none") return "#20242a";
    colorProbe.fillStyle = "#000001";
    colorProbe.fillStyle = value;
    const result = colorProbe.fillStyle;
    if (result === "#000001") return "#20242a";           // unparsable colour
    if (/^#[0-9a-f]{6}$/i.test(result)) return result;
    const rgb = result.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/);
    return rgb ? "#" + rgb.slice(1, 4).map(n => Number(n).toString(16).padStart(2, "0")).join("") : "#20242a";
  }

  const multiply = (p, q) => [
    p[0] * q[0] + p[2] * q[1], p[1] * q[0] + p[3] * q[1],
    p[0] * q[2] + p[2] * q[3], p[1] * q[2] + p[3] * q[3],
    p[0] * q[4] + p[2] * q[5] + p[4], p[1] * q[4] + p[3] * q[5] + p[5],
  ];

  function parseTransform(value) {
    let matrix = [1, 0, 0, 1, 0, 0];
    for (const [, name, args] of String(value || "").matchAll(/(\w+)\s*\(([^)]*)\)/g)) {
      const n = args.trim().split(/[\s,]+/).map(Number);
      let step = null;
      if (name === "translate") step = [1, 0, 0, 1, n[0] || 0, n[1] || 0];
      else if (name === "scale") step = [n[0], 0, 0, n.length > 1 ? n[1] : n[0], 0, 0];
      else if (name === "rotate") {
        const angle = (n[0] || 0) * Math.PI / 180, c = Math.cos(angle), s = Math.sin(angle), cx = n[1] || 0, cy = n[2] || 0;
        step = [c, s, -s, c, cx - c * cx + s * cy, cy - s * cx - c * cy];
      } else if (name === "matrix" && n.length === 6) step = n;
      if (step && step.every(Number.isFinite)) matrix = multiply(matrix, step);
    }
    return matrix;
  }

  function ancestorMatrix(node) {
    const chain = [];
    for (let element = node; element && element.nodeType === 1; element = element.parentNode) chain.unshift(element);
    return chain.reduce((matrix, element) => multiply(matrix, parseTransform(element.getAttribute("transform"))), [1, 0, 0, 1, 0, 0]);
  }

  // Several <tspan> lines become one multi-line object; otherwise the text is collapsed to one line.
  function svgTextContent(node) {
    const spans = [...node.children].filter(child => child.nodeName.toLowerCase() === "tspan");
    const lineStarts = spans.filter(span => span.hasAttribute("x") || span.hasAttribute("y") || span.hasAttribute("dy"));
    const clean = value => value.replace(/\s+/g, " ").trim();
    if (spans.length > 1 && lineStarts.length > 1) {
      return spans.map(span => clean(span.textContent)).filter(Boolean).join("\n").slice(0, 500);
    }
    return clean(node.textContent).slice(0, 500);
  }

  function fontFamilyFor(family) {
    if (/mono|courier/i.test(family)) return "Courier New";
    if (/times/i.test(family)) return "Times New Roman";
    if (/georgia/i.test(family)) return "Georgia";
    if (/verdana/i.test(family)) return "Verdana";
    if (/tahoma/i.test(family)) return "Tahoma";
    if (/trebuchet/i.test(family)) return "Trebuchet MS";
    if (/serif/i.test(family) && !/sans/i.test(family)) return "Times New Roman";
    return "Arial";
  }

  function svgTextSpec(node, doc, view) {
    if (node.closest(SKIPPED_PARENTS)) return null;
    const text = svgTextContent(node);
    if (!text) return null;
    const span = node.querySelector("tspan[x]") || node.querySelector("tspan[y]");
    const rawX = node.getAttribute("x") ?? span?.getAttribute("x");
    const rawY = node.getAttribute("y") ?? span?.getAttribute("y");
    if (rawX == null && rawY == null) return null;
    const x = parseFloat(rawX) || 0, y = parseFloat(rawY) || 0;
    const matrix = ancestorMatrix(node);
    const px = matrix[0] * x + matrix[2] * y + matrix[4];
    const py = matrix[1] * x + matrix[3] * y + matrix[5];
    const factor = Math.hypot(matrix[0], matrix[1]) || 1;
    const angle = Math.atan2(matrix[1], matrix[0]) * 180 / Math.PI;

    const fontSize = Math.max(8, Math.min(200, Math.round((parseFloat(inherited(node, "font-size")) || 16) * factor * view.scale)));
    const anchor = inherited(node, "text-anchor");
    const align = anchor === "middle" ? "center" : anchor === "end" ? "right" : "left";
    const spacing = (parseFloat(inherited(node, "letter-spacing")) || 0) * factor * view.scale;
    const multiline = text.includes("\n");
    return {
      text,
      left: (px - view.x) * view.scale,
      // SVG y is the first baseline; objects are positioned by the middle (one line) or the top (several lines).
      top: (py - view.y) * view.scale - (multiline ? 0.93 : 0.35) * fontSize,
      originX: align, originY: multiline ? "top" : "center", textAlign: align,
      fontSize, fill: svgColor(inherited(node, "fill"), doc),
      fontFamily: fontFamilyFor(inherited(node, "font-family")),
      fontWeight: /^(bold|bolder|[6-9]00)$/.test(inherited(node, "font-weight")) ? "bold" : "normal",
      fontStyle: /^(italic|oblique)$/.test(inherited(node, "font-style")) ? "italic" : "normal",
      angle: Math.abs(angle) > 0.01 ? round(((angle % 360) + 360) % 360) : 0,
      charSpacing: spacing > 0 ? (spacing / fontSize) * 1000 : 0,
    };
  }

  function setBackground(url) {
    return new Promise((resolve, reject) => {
      fabric.Image.fromURL(url, image => {
        if (!image || !image.width) { reject(new Error("image")); return; }
        const scale = Math.min(canvas.getWidth() / image.width, canvas.getHeight() / image.height);
        image.set({
          originX: "left", originY: "top", scaleX: scale, scaleY: scale,
          left: (canvas.getWidth() - image.width * scale) / 2,
          top: (canvas.getHeight() - image.height * scale) / 2,
        });
        canvas.setBackgroundImage(image, () => resolve());
      });
    });
  }

  // Returns the text specs found in the SVG; the drawing minus those texts is the background.
  async function loadSvgTemplate(url) {
    const response = await fetch(url, { credentials: "same-origin" });
    if (!response.ok) throw new Error("svg");
    const doc = new DOMParser().parseFromString(await response.text(), "image/svg+xml");
    const svg = doc.documentElement;
    if (svg.nodeName.toLowerCase() !== "svg" || doc.querySelector("parsererror")) throw new Error("svg");
    const box = (svg.getAttribute("viewBox") || "").trim().split(/[\s,]+/).map(Number);
    const hasBox = box.length === 4 && box.every(Number.isFinite) && box[2] > 0 && box[3] > 0;
    const view = {
      x: hasBox ? box[0] : 0, y: hasBox ? box[1] : 0,
      w: hasBox ? box[2] : (parseFloat(svg.getAttribute("width")) || 900),
      h: hasBox ? box[3] : (parseFloat(svg.getAttribute("height")) || 540),
    };
    view.scale = view.w >= view.h ? 900 / view.w : 1000 / view.h;
    canvas.setDimensions({ width: Math.round(view.w * view.scale), height: Math.round(view.h * view.scale) });
    svgRules = readStyleRules(svg);

    const specs = [];
    for (const node of [...svg.querySelectorAll("text")]) {
      if (specs.length >= MAX_OBJECTS) break;
      const spec = svgTextSpec(node, doc, view);
      if (!spec) continue;               // not expressible as an object: it stays in the background
      specs.push(spec);
      node.remove();
    }
    svg.setAttribute("width", String(view.w));
    svg.setAttribute("height", String(view.h));
    const blobUrl = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(svg)], { type: "image/svg+xml" }));
    try { await setBackground(blobUrl); } finally { URL.revokeObjectURL(blobUrl); }
    return specs;
  }

  // Saved positions are in the canvas size of the moment they were saved.
  function scaleSpec(spec, ratio) {
    if (!(ratio > 0) || Math.abs(ratio - 1) < 0.01) return spec;
    return {
      ...spec,
      left: spec.left * ratio, top: spec.top * ratio,
      fontSize: Math.max(8, Math.min(200, (spec.fontSize || 32) * ratio)),
    };
  }

  // ---- start ---------------------------------------------------------------
  async function init() {
    setSizeFromTemplate();
    let seeds = [];
    const url = root.dataset.background || "";
    if (url) {
      try {
        if (/\.svg(\?|$)/i.test(url)) seeds = await loadSvgTemplate(url);
        else await setBackground(url);
      } catch {
        message.textContent = "Không tải được ảnh mẫu; bạn vẫn có thể thêm chữ.";
      }
    }
    // Saved text always wins; the template's own text is only used to start a brand-new design.
    const saved = savedObjects.filter(item => item && typeof item.text === "string" && item.text.trim());
    const ratio = savedCanvas && savedCanvas.width > 0 ? canvas.getWidth() / savedCanvas.width : 1;
    const specs = saved.length
      ? saved.map(item => (item.left === undefined && item.x !== undefined ? fromLegacy(item) : scaleSpec(item, ratio)))
      : (root.dataset.seed === "1" ? seeds : []);
    let failed = 0;
    restoring = true;
    specs.slice(0, MAX_OBJECTS).forEach(spec => {
      try { canvas.add(makeText(spec)); } catch { failed += 1; }   // one bad object must not drop the rest
    });
    restoring = false;
    if (failed) message.textContent = `Không khôi phục được ${failed} đối tượng chữ đã lưu.`;
    fit();
    canvas.requestRenderAll();
    record();
  }

  // ---- save ----------------------------------------------------------------
  document.getElementById("save-design").addEventListener("click", async () => {
    const editing = activeText();
    if (editing && editing.isEditing) editing.exitEditing();
    canvas.discardActiveObject();
    canvas.requestRenderAll();
    message.textContent = "Đang lưu…";
    try {
      let image = null;
      try { image = canvas.toDataURL({ format: "png", multiplier: 1 }); } catch { image = null; }
      const response = await fetch(root.dataset.saveUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": root.dataset.csrf },
        body: JSON.stringify({
          canvas: { width: Math.round(canvas.getWidth()), height: Math.round(canvas.getHeight()) },
          objects: snapshot(),
          image,
        }),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || "Không thể lưu thiết kế.");
      message.textContent = "Đã lưu thiết kế.";
      if (result.redirect) window.location.assign(result.redirect);
    } catch (error) {
      message.textContent = error.message || "Không thể lưu thiết kế. Kiểm tra kết nối rồi thử lại.";
    }
  });

  init().catch(() => { message.textContent = "Không thể mở thiết kế. Vui lòng tải lại trang."; });
})();