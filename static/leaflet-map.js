/* DNS Inspector - Leaflet + OpenStreetMap DNS Destinations map (Issue #69)
 *
 * Supersedes the amCharts map experiment. This is now the primary map
 * renderer: Leaflet owns pan/zoom/marker placement as a real geographic
 * viewport (real tiles that move/scale with markers), replacing the fixed
 * SVG "wallpaper" the previous renderer drew underneath a separately
 * projected overlay.
 *
 * Loading contract, unchanged from the amCharts experiment and from Issue
 * #61's fix: fetchDestinationMap() in the main inline <script> remains the
 * only owner of /api/analytics/map network requests (AbortController,
 * monotonic sequence, in-flight guard, payload fingerprint all untouched).
 * This file only ever replaces window.renderDestinationMap, the single
 * function fetchDestinationMap() calls to paint whatever it fetched.
 *
 * Fallback contract: if the Leaflet library failed to load, or map
 * initialization throws for any reason, this file returns without touching
 * window.renderDestinationMap -- the legacy SVG renderer already defined by
 * the main inline <script> stays active untouched, so Leaflet is only ever
 * a fallback-guarded upgrade, never a hard dependency.
 *
 * Selection stays synchronized with the country breakdown panel by reusing
 * the exact same mapSelectCountry()/renderMapDetail()/mapLastPayload state
 * the legacy renderer and breakdown rows already share (Issue #63) --
 * clicking a marker here calls the identical shared function a breakdown
 * row click already calls, so the two selection surfaces can never diverge.
 */
(function () {
  "use strict";

  if (!window.L) {
    console.warn("[dns-map-leaflet] Leaflet library unavailable; keeping legacy SVG map");
    return;
  }

  const host = document.getElementById("destination-map");
  if (!host) return;

  // Captured before window.renderDestinationMap is overridden below, so a
  // map-init failure discovered later (e.g. the library loaded but L.map()
  // itself throws) can still fall back to the real legacy SVG renderer
  // instead of leaving the widget blank -- required fallback contract,
  // not just a load-time check.
  const legacyRenderDestinationMap = typeof window.renderDestinationMap === "function" ? window.renderDestinationMap : null;

  const BASEMAP_DEFINITIONS = {
    "OpenStreetMap": {
      url: "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      options: {
        maxZoom: 19,
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors',
      },
    },
    "OpenTopoMap": {
      url: "https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png",
      options: {
        maxZoom: 17,
        subdomains: ["a", "b", "c"],
        attribution: 'Kartendaten: &copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a>-Mitwirkende, SRTM | Kartendarstellung: &copy; <a href="https://opentopomap.org/" target="_blank" rel="noopener noreferrer">OpenTopoMap</a> (CC-BY-SA)',
      },
    },
    "Satellite (Esri)": {
      url: "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
      options: {
        maxZoom: 19,
        attribution: 'Tiles &copy; Esri &mdash; Source: Esri, Maxar, Earthstar Geographics, and the GIS User Community',
      },
    },
    "Dark / NOC": {
      url: "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
      options: {
        maxZoom: 19,
        subdomains: "abcd",
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions" target="_blank" rel="noopener noreferrer">CARTO</a>',
      },
    },
  };

  const state = { map: null, layers: null, baseLayers: null, initialized: false, failed: false };

  const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
  const reducedMotion = () =>
    !!(
      (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) ||
      document.documentElement.dataset.motion === "reduced" ||
      (typeof prefs !== "undefined" && prefs.reducedMotion)
    );
  const activeMode = () => (typeof prefs !== "undefined" && prefs.mapMode === "destinations" ? "destinations" : "countries");
  const activeTheme = () => (typeof mapActiveTheme === "function" ? mapActiveTheme() : "bemo-accent");
  const metricValue = (entity) => (typeof mapMetricValue === "function" ? mapMetricValue(entity) : num(entity.observation_count));
  const themeColor = (ratio, theme) => (typeof mapThemeColor === "function" ? mapThemeColor(ratio, theme) : "#58a6ff");
  const escapeHtml = (v) => (typeof esc === "function" ? esc(v) : String(v == null ? "" : v));

  function ensureMap() {
    if (state.initialized) return true;
    if (state.failed) return false;
    try {
      host.classList.add("leaflet-map-host");
      const map = L.map(host, {
        worldCopyJump: true,
        minZoom: 1,
        maxZoom: 18,
        zoomAnimation: !reducedMotion(),
        fadeAnimation: !reducedMotion(),
        markerZoomAnimation: !reducedMotion(),
      }).setView([20, 0], 2);

      const baseLayers = {};
      Object.entries(BASEMAP_DEFINITIONS).forEach(([label, def]) => {
        baseLayers[label] = L.tileLayer(def.url, def.options);
      });
      baseLayers["OpenStreetMap"].addTo(map);
      L.control.layers(baseLayers, null, { collapsed: true, position: "topright" }).addTo(map);
      state.baseLayers = baseLayers;

      // Future-ready layer-group structure (Issue #69): only the two
      // datasets that already exist (country aggregates, observed
      // destination coordinates) are populated. Additional infrastructure
      // datasets (Google/AWS/Azure/Cloudflare/CDN PoPs etc.), if they are
      // ever added to the backend, can register another named L.layerGroup()
      // here the same way, without replacing the map engine.
      state.layers = {
        countries: L.layerGroup().addTo(map),
        destinations: L.layerGroup(),
        routes: L.layerGroup(),
      };

      map.on("zoomend moveend", () => {
        if (!mapLastPayload) return;
        if (activeMode() === "destinations") renderDestinations(mapLastPayload, mapLastPayload.capabilities || {});
      });

      state.map = map;
      state.initialized = true;
      return true;
    } catch (err) {
      console.warn("[dns-map-leaflet] failed to initialize Leaflet map; keeping legacy SVG map", err);
      state.failed = true;
      state.map = null;
      state.layers = null;
      // Undo any partial Leaflet DOM/state so the legacy SVG fallback (which
      // replaces host.innerHTML wholesale but doesn't touch the element's
      // own class list) renders into a clean host element.
      host.classList.remove("leaflet-map-host", "leaflet-container");
      host.innerHTML = "";
      return false;
    }
  }

  function banner(text, actionHtml) {
    let el = host.querySelector(".leaflet-status-banner");
    if (!text) {
      if (el) el.remove();
      return;
    }
    if (!el) {
      el = document.createElement("div");
      el.className = "map-status-banner leaflet-status-banner";
      host.appendChild(el);
    }
    el.innerHTML = text + (actionHtml ? `<div class="map-status-action">${actionHtml}</div>` : "");
  }

  function clearLayers() {
    if (!state.layers) return;
    state.layers.countries.clearLayers();
    state.layers.destinations.clearLayers();
    state.layers.routes.clearLayers();
  }

  function setVisibleLayer(mode) {
    if (!state.map || !state.layers) return;
    if (mode === "destinations") {
      if (!state.map.hasLayer(state.layers.destinations)) state.layers.destinations.addTo(state.map);
      if (!state.map.hasLayer(state.layers.routes)) state.layers.routes.addTo(state.map);
      if (state.map.hasLayer(state.layers.countries)) state.map.removeLayer(state.layers.countries);
    } else {
      if (!state.map.hasLayer(state.layers.countries)) state.layers.countries.addTo(state.map);
      if (state.map.hasLayer(state.layers.destinations)) state.map.removeLayer(state.layers.destinations);
      if (state.map.hasLayer(state.layers.routes)) state.map.removeLayer(state.layers.routes);
    }
  }

  // Spherical linear interpolation between two lat/lon points -- used to draw
  // a great-circle "air route style" arc rather than a straight Mercator
  // line. This is explicitly a geographic/visual path only, never presented
  // as the real network route DNS traffic took (Issue #88 #5).
  function toRad(d) { return (d * Math.PI) / 180; }
  function toDeg(r) { return (r * 180) / Math.PI; }
  function latLonToVec(lat, lon) {
    const la = toRad(lat), lo = toRad(lon);
    return [Math.cos(la) * Math.cos(lo), Math.cos(la) * Math.sin(lo), Math.sin(la)];
  }
  function vecToLatLon(v) {
    const lat = toDeg(Math.asin(Math.max(-1, Math.min(1, v[2]))));
    const lon = toDeg(Math.atan2(v[1], v[0]));
    return [lat, lon];
  }
  function greatCircleArc(lat1, lon1, lat2, lon2, segments) {
    const v0 = latLonToVec(lat1, lon1), v1 = latLonToVec(lat2, lon2);
    const dot = Math.max(-1, Math.min(1, v0[0] * v1[0] + v0[1] * v1[1] + v0[2] * v1[2]));
    const omega = Math.acos(dot);
    if (omega < 1e-6) return [[lat1, lon1], [lat2, lon2]];
    const points = [];
    for (let i = 0; i <= segments; i++) {
      const t = i / segments;
      const a = Math.sin((1 - t) * omega) / Math.sin(omega);
      const b = Math.sin(t * omega) / Math.sin(omega);
      const v = [a * v0[0] + b * v1[0], a * v0[1] + b * v1[1], a * v0[2] + b * v1[2]];
      points.push(vecToLatLon(v));
    }
    return points;
  }

  function renderRoutes(data, capabilities, points) {
    if (!state.layers) return;
    state.layers.routes.clearLayers();
    const routesEnabled = typeof prefs !== "undefined" && !!prefs.mapRoutes;
    if (!routesEnabled) return;
    if (!capabilities || (!capabilities.coordinates && !capabilities.datacenter)) return;
    const origin = data && data.origin;
    if (!origin || origin.lat == null || origin.lon == null) return;
    points = (points || []).filter((p) => p.lat != null && p.lon != null);
    if (!points.length) return;
    const maxVal = Math.max(1, ...points.map((p) => metricValue(p)));
    const theme = activeTheme();
    const originMarker = L.circleMarker([origin.lat, origin.lon], {
      radius: 5, color: "#fff", weight: 2, fillColor: "#58a6ff", fillOpacity: 1, interactive: true,
    }).bindTooltip(`${escapeHtml(origin.label || "Configured origin")} — visualization origin, not a verified location`, { direction: "top" });
    state.layers.routes.addLayer(originMarker);
    points.forEach((p) => {
      const ratio = metricValue(p) / maxVal;
      const arcPoints = greatCircleArc(origin.lat, origin.lon, p.lat, p.lon, 48);
      const line = L.polyline(arcPoints, {
        color: themeColor(ratio, theme),
        weight: Math.max(1, 1 + ratio * 2.5),
        opacity: 0.22 + ratio * 0.35,
        interactive: true,
      });
      const label = p.city || p.country_name || p.country_code || "Unknown";
      const provLabel = typeof provenanceLabel === "function" ? provenanceLabel(p) : null;
      line.bindTooltip(`${escapeHtml(label)}${provLabel ? ` (${escapeHtml(provLabel)})` : ""}: ${num(p.observation_count)} observations — geographic/visual path, not the real network route`, { sticky: true });
      line.on("click", () => activateCluster(p, data, capabilities));
      state.layers.routes.addLayer(line);
    });
  }

  function bubbleIcon(size, color, selected) {
    return L.divIcon({
      className: "leaflet-dns-marker" + (selected ? " leaflet-dns-marker-selected" : ""),
      html: `<span style="background:${color}"></span>`,
      iconSize: [size, size],
    });
  }

  function renderCountries(data) {
    banner(null);
    clearLayers();
    setVisibleLayer("countries");
    const theme = activeTheme();
    const allCountries = data?.countries || [];
    const countries = allCountries.filter((c) => c.centroid);
    if (!countries.length) {
      banner(
        allCountries.length
          ? `${escapeHtml(allCountries.length)} geolocated countr${allCountries.length === 1 ? "y" : "ies"} have no map coordinates configured yet &mdash; see the country list alongside the map.`
          : "No geolocated destinations yet. This fills in as domains are queried and their actual DNS answers get matched against the configured GeoIP database."
      );
      renderMapDetail(null);
      return;
    }
    const maxVal = Math.max(1, ...countries.map((c) => metricValue(c)));
    countries.forEach((c) => {
      const [lat, lon] = c.centroid;
      const ratio = metricValue(c) / maxVal;
      const color = themeColor(ratio, theme);
      const size = Math.round(14 + Math.sqrt(ratio) * 30);
      const selected = mapSelectedCountry === c.country_code;
      const marker = L.marker([lat, lon], {
        icon: bubbleIcon(size, color, selected),
        title: `${c.country_name || c.country_code}: ${num(c.observation_count)} observations`,
        alt: c.country_name || c.country_code || "",
        keyboard: true,
      });
      marker.on("click", () => mapSelectCountry(c.country_code));
      state.layers.countries.addLayer(marker);
    });
  }

  /* Bounded lat/lon grid clustering, independent of the legacy SVG's own
     pixel-space clusterDestinationPoints() (that one assumes an
     equirectangular projection fixed to a 720x360 canvas; Leaflet works in
     real lat/lon and re-projects on every zoom/pan itself). The cell shrinks
     as the real Leaflet zoom level increases, so zooming in reveals smaller
     clusters/individual points the same way the legacy renderer's own
     zoom-dependent clustering did. */
  function clusterPoints(points, zoom) {
    const cellDeg = Math.max(0.4, 40 / Math.pow(1.6, zoom));
    const cells = new Map();
    points.forEach((p) => {
      if (p.lat == null || p.lon == null) return;
      const key = Math.round(p.lat / cellDeg) + ":" + Math.round(p.lon / cellDeg);
      let bucket = cells.get(key);
      if (!bucket) {
        bucket = { key, points: [], observation_count: 0, domain_count: 0, sumLat: 0, sumLon: 0 };
        cells.set(key, bucket);
      }
      bucket.points.push(p);
      bucket.sumLat += p.lat;
      bucket.sumLon += p.lon;
      bucket.observation_count += p.observation_count || 0;
      bucket.domain_count += p.domain_count || 0;
    });
    return Array.from(cells.values()).map((b) => {
      const provenanceSet = new Set(b.points.map((p) => p.provenance).filter(Boolean));
      const singlePoint = b.points.length === 1 ? b.points[0] : null;
      return {
        key: b.key,
        lat: b.sumLat / b.points.length,
        lon: b.sumLon / b.points.length,
        unique_ip_count: b.points.length,
        observation_count: b.observation_count,
        domain_count: b.domain_count,
        country_code: b.points[0].country_code,
        country_name: b.points[0].country_name,
        city: singlePoint ? singlePoint.city : null,
        provenance: provenanceSet.size === 1 ? Array.from(provenanceSet)[0] : (provenanceSet.size > 1 ? "mixed" : null),
        provider: singlePoint ? singlePoint.provider : null,
        region: singlePoint ? singlePoint.region : null,
        sample_domains: Array.from(new Set(b.points.flatMap((p) => p.sample_domains || []))).slice(0, 5),
      };
    });
  }

  function renderDestinations(data, capabilities) {
    banner(null);
    clearLayers();
    setVisibleLayer("destinations");
    if (!capabilities || (!capabilities.coordinates && !capabilities.datacenter)) {
      banner(
        "Coordinate-level destination data is unavailable &mdash; only a country GeoIP database is configured. Configure a city/coordinate-capable GeoIP database, or a curated known-datacenter database, to enable Destinations mode, or switch to Countries. See docs/GEOIP.md."
      );
      renderMapDetail(null);
      return;
    }
    const points = (data?.destinations || []).filter((p) => p.lat != null && p.lon != null);
    if (!points.length) {
      banner(
        "No geolocated destination coordinates yet. This fills in as domains are queried and their actual DNS answers get matched against the configured city/coordinate or known-datacenter GeoIP database."
      );
      renderMapDetail(null);
      return;
    }
    const zoom = state.map.getZoom();
    const clusters = clusterPoints(points, zoom);
    const maxVal = Math.max(1, ...clusters.map((c) => metricValue(c)));
    const theme = activeTheme();
    clusters.forEach((c) => {
      const ratio = metricValue(c) / maxVal;
      const color = themeColor(ratio, theme);
      const size = Math.round(12 + Math.sqrt(ratio) * 26);
      const selected = mapSelectedDestinationKey === c.key;
      const provLabel = typeof provenanceLabel === "function" ? provenanceLabel(c) : null;
      const label =
        (c.unique_ip_count > 1
          ? `${num(c.unique_ip_count)} destinations: ${num(c.observation_count)} observations, ${num(c.domain_count)} domains`
          : `${c.city || c.country_name || c.country_code || "Unknown"}: ${num(c.observation_count)} observations, ${num(c.domain_count)} domains`) +
        (provLabel ? ` — ${provLabel}` : "");
      const marker = L.marker([c.lat, c.lon], {
        icon: bubbleIcon(size, color, selected),
        title: label,
        keyboard: true,
      });
      marker.on("click", () => activateCluster(c, data, capabilities));
      state.layers.destinations.addLayer(marker);
    });
    renderRoutes(data, capabilities, clusters);
  }

  function activateCluster(cluster, data, capabilities) {
    if (cluster.unique_ip_count > 1 && state.map.getZoom() < state.map.getMaxZoom()) {
      state.map.setView([cluster.lat, cluster.lon], Math.min(state.map.getMaxZoom(), state.map.getZoom() + 2));
      return; // the zoomend/moveend handler above re-renders/re-clusters at the new zoom
    }
    mapSelectedDestinationKey = mapSelectedDestinationKey === cluster.key ? null : cluster.key;
    // Issue #63 guidance, unchanged: show the real detail card before the
    // (more expensive) marker re-render, so the click path never risks
    // losing/invalidating detail state behind that re-render.
    renderMapDetail(mapSelectedDestinationKey ? cluster : null, "destination");
    renderDestinations(data, capabilities);
  }

  function update(data) {
    mapLastPayload = data;

    if (!ensureMap()) {
      // Leaflet's library loaded, but a real map instance could not be
      // created (or previously failed) -- delegate straight to the actual
      // legacy SVG renderer rather than leaving the widget blank. This is
      // the fallback contract itself, not just a best-effort log line.
      if (legacyRenderDestinationMap) legacyRenderDestinationMap(data);
      return;
    }

    const provider = data?.provider || {};
    const capabilities = data?.capabilities || {};
    const mode = activeMode();

    const subtitleEl = document.getElementById("destination-map-subtitle");
    if (subtitleEl) {
      subtitleEl.textContent =
        mode === "destinations"
          ? "Real observed DNS destination IPs plotted on an OpenStreetMap-based map, clustered when nearby — not verified physical server locations."
          : "Country-level aggregate of resolved DNS response IPs on an OpenStreetMap-based map — not verified physical server locations. CDN, anycast and multi-region destinations resolve to whichever country answered.";
    }
    const legendMetricEl = document.getElementById("map-legend-metric-label");
    if (legendMetricEl) legendMetricEl.textContent = mapMetricLabel();

    // Issue #63 contract, unchanged: the breakdown/history panel renders
    // from the exact same payload as the map, regardless of mode/diagnostic
    // state below.
    renderMapBreakdown(data);
    renderMapBreakdownHistory(data);

    const basemapSelect = document.getElementById("map-basemap-select");
    if (basemapSelect && !basemapSelect.dataset.leafletHidden) {
      // The four legacy "basemap" presets (stylized dot-matrix background
      // treatments) don't apply once Leaflet/OSM is the real map viewport;
      // the preference itself is left untouched in storage so it still
      // governs the legacy SVG fallback if this ever falls back to it.
      basemapSelect.style.display = "none";
      basemapSelect.dataset.leafletHidden = "1";
    }

    const diagState = data?.diagnostics?.state;
    if (diagState === "load_failed") {
      clearLayers();
      banner(
        "GEOIP_DB_PATH is set, but the configured database failed to load. Check that the file exists at that path inside the container and is readable, then restart. See docs/GEOIP.md."
      );
      renderMapDetail(null);
      return;
    }
    if (!provider.configured && !capabilities.coordinates && !capabilities.datacenter) {
      clearLayers();
      banner("No GeoIP database configured &mdash; destinations are reported as unmapped rather than guessed. See docs/GEOIP.md to enable the map.");
      renderMapDetail(null);
      return;
    }

    if (mode === "destinations") renderDestinations(data, capabilities);
    else renderCountries(data);
  }

  window.renderDestinationMap = update;

  document.getElementById("map-zoom-in-btn")?.addEventListener("click", () => state.map?.zoomIn());
  document.getElementById("map-zoom-out-btn")?.addEventListener("click", () => state.map?.zoomOut());
  document.getElementById("map-fit-btn")?.addEventListener("click", () => {
    if (!state.map || !mapLastPayload) return;
    const mode = activeMode();
    const points =
      mode === "destinations"
        ? (mapLastPayload.destinations || []).filter((p) => p.lat != null && p.lon != null).map((p) => [p.lat, p.lon])
        : (mapLastPayload.countries || []).filter((c) => c.centroid).map((c) => c.centroid);
    if (!points.length) return;
    state.map.fitBounds(L.latLngBounds(points), { padding: [24, 24], maxZoom: state.map.getMaxZoom() });
  });
  document.getElementById("map-reset-btn")?.addEventListener("click", () => {
    state.map?.setView([20, 0], 2);
  });
})();
