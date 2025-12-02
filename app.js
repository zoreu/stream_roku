const video = document.getElementById("iptv-video");
const playerContainer = document.getElementById("playerContainer");
const loading = document.getElementById("loading");
const playingChannelEl = document.getElementById("playingChannel");

let hls = null;
let isPlayerOpen = false;

function destroyPlayer() {
    if (hls) { hls.destroy(); hls = null; }
    video.pause();
    video.removeAttribute("src");
    video.load();
    loading.style.display = "block";
}

function closePlayer() {
    if (!isPlayerOpen) return;
    isPlayerOpen = false;
    playerContainer.style.display = "none";
    destroyPlayer();
    playingChannelEl.textContent = "Carregando...";
}

function playChannel(url, name) {
    if (isPlayerOpen) destroyPlayer();
    isPlayerOpen = true;

    playerContainer.style.display = "flex";
    playingChannelEl.textContent = name;

    const proxyUrl = `http://${proxyHost}/hlsretry?url=${encodeURIComponent(url)}`;

    if (Hls.isSupported()) {
        hls = new Hls({ lowLatencyMode: true, backBufferLength: 90 });
        hls.loadSource(proxyUrl);
        hls.attachMedia(video);
        hls.on(Hls.Events.MANIFEST_PARSED, () => {
            video.play().catch(() => {});
            loading.style.display = "none";
        });
    } else if (video.canPlayType("application/vnd.apple.mpegurl")) {
        video.src = proxyUrl;
        video.play().catch(() => {});
        loading.style.display = "none";
    }
}

window.addEventListener("popstate", () => { if (isPlayerOpen) closePlayer(); });
document.addEventListener("keydown", e => { if (e.key === "Escape" && isPlayerOpen) closePlayer(); });
playerContainer.addEventListener("click", e => { if (e.target === playerContainer) closePlayer(); });

function loadList(id) {
    document.getElementById("categories").innerHTML =
        '<div style="grid-column:1/-1;text-align:center;padding:40px;color:#94a3b8;">Carregando...</div>';

    fetch(`/oneplay?lista=lista${id}`)
        .then(r => r.text())
        .then(parseM3U);
}

function parseM3U(content) {
    const lines = content.split("\n");
    const channels = [];
    let current = null;

    for (let line of lines) {
        line = line.trim();

        if (line.startsWith("#EXTINF:")) {
            const name = (line.match(/,(.*)$/)?.[1] || "Canal").trim();
            const logo = line.match(/tvg-logo="([^"]+)"/i)?.[1] || "";
            const group = line.match(/group-title="([^"]+)"/i)?.[1] || "Outros";

            current = { name, logo, group, url: "" };
        } else if (line.startsWith("http") && current) {
            current.url = line;
            channels.push(current);
            current = null;
        }
    }

    window.allChannels = channels;

    const groups = [...new Set(channels.map(c => c.group))].sort();

    document.getElementById("categories").innerHTML =
        groups.map(g => `
            <div class="category" onclick="showGroup('${g.replace(/'/g, "\\'")}')">
                <i class="fas fa-tv"></i>
                <div>${g}</div>
                <small>${channels.filter(c => c.group === g).length} canais</small>
            </div>
        `).join("");
}

function showGroup(group) {
    const filtered = window.allChannels.filter(c => c.group === group);

    document.getElementById("channels").innerHTML =
        filtered.map(c => `
            <div class="channel-card" onclick="playChannel('${c.url.replace(/'/g, "\\'")}', '${c.name.replace(/'/g, "\\'")}')">
                <img src="${c.logo}" class="channel-logo">
                <div class="channel-name">${c.name}</div>
            </div>
        `).join("");

    document.getElementById("channels").style.display = "grid";
}

for (let i = 1; i <= 10; i++) {
    const num = i.toString().padStart(2, "0");

    const btn = document.createElement("div");
    btn.className = "server-btn";
    btn.textContent = "Lista " + num;

    btn.onclick = () => {
        document.querySelectorAll(".server-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        loadList(num);
    };

    if (i === 1) btn.classList.add("active");

    document.getElementById("serverSelector").appendChild(btn);
}

loadList("01");
