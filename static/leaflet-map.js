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

  const OSM_TILE_URL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png";
  const OSM_ATTRIBUTION =
    '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors';

  /* Issue #72: basemap layer control. OpenStreetMap Standard stays the
   * always-on, no-key default; Tracestrack Topo is a second selectable
   * basemap (Tracestrack's topo style is itself rendered from OpenStreetMap
   * data, so both OSM and Tracestrack attribution are required together).
   * Tracestrack requires a free personal API key (registration at
   * https://tracestrack.com/) -- there is no working no-key tile URL for it,
   * so the key is read live from Leaflet's own `{key}` URL-template
   * substitution (options.key) rather than baked into the URL string; see
   * the Settings-adjacent "Tracestrack API key" field in the map controls
   * and mapUpdateTracestrackKey() below, which updates this layer in place
   * when that field changes.
   *
   * **Unverified in this sandbox**: this session's sandbox had no outbound
   * network access to re-confirm Tracestrack's exact current tile URL
   * path/style token/file extension or attribution wording live against
   * https://tracestrack.com/ (the same disclosed limitation recorded
   * against numerous other 0.8.5.x hand-offs in docs/CURRENT_STATE.md, e.g.
   * the DB-IP update URL templates). TRACESTRACK_TILE_URL_TEMPLATE is a
   * single overridable constant specifically so an operator/maintainer can
   * correct it without touching any other map code once confirmed against
   * Tracestrack's current documentation.
   *
   * This object is the extension point for Section 5 of Issue #72 ("future
   * layer architecture"): add another `{ name: { url, options } }` entry
   * here to register a further basemap without touching ensureMap()'s
   * control-building logic below. */
  const TRACESTRACK_TILE_URL_TEMPLATE = "https://tile.tracestrack.com/topo__/{z}/{x}/{y}.png?key={key}";
  const TRACESTRACK_ATTRIBUTION =
    '&copy; <a href="https://www.tracestrack.com/" target="_blank" rel="noopener noreferrer">Tracestrack</a>, map data ' +
    '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors';
  const LEAFLET_BASEMAPS = {
    "OpenStreetMap Standard": { url: OSM_TILE_URL, options: { maxZoom: 19, attribution: OSM_ATTRIBUTION } },
    "Tracestrack Topo": {
      url: TRACESTRACK_TILE_URL_TEMPLATE,
      options: { maxZoom: 18, attribution: TRACESTRACK_ATTRIBUTION, key: "" },
    },
  };

  /* Section 3 (Issue #72): Data Centre / DTC pins -- an additive, off-by-
   * default overlay layer, completely independent of Countries/Destinations
   * mode and of /api/analytics/map. This is a small, explicit, hand-
   * maintained seed list (not a claim of comprehensive coverage) of major
   * public cloud regions/PoPs, at city-level precision only (never a
   * specific building/address) with each entry citing the provider's own
   * public documentation as its source, per this issue's explicit
   * instruction not to invent DTC locations. **This session's sandbox had
   * no outbound network access to re-verify these entries live** -- an
   * operator/maintainer should confirm them against each cited source
   * before relying on this layer in production, the same disclosed-
   * limitation pattern used elsewhere in this project. Extend this array
   * (or replace it with a fetch from a future backend
   * `infrastructure_locations` table) to add more providers/PoPs -- no
   * rendering code below needs to change to do so. */
  const DTC_LOCATIONS = [
    { id: "aws-us-east-1", provider: "AWS", label: "AWS us-east-1 (N. Virginia)", city: "Ashburn, Virginia, US", lat: 39.04, lon: -77.49, source: "https://aws.amazon.com/about-aws/global-infrastructure/regions_az/" },
    { id: "aws-eu-west-1", provider: "AWS", label: "AWS eu-west-1 (Ireland)", city: "Dublin, Ireland", lat: 53.35, lon: -6.26, source: "https://aws.amazon.com/about-aws/global-infrastructure/regions_az/" },
    { id: "gcp-us-central1", provider: "Google Cloud", label: "GCP us-central1", city: "Council Bluffs, Iowa, US", lat: 41.26, lon: -95.86, source: "https://cloud.google.com/about/locations" },
    { id: "azure-eastus", provider: "Azure", label: "Azure East US", city: "Boydton, Virginia, US", lat: 36.67, lon: -78.39, source: "https://azure.microsoft.com/en-us/explore/global-infrastructure/geographies/" },
    { id: "cloudflare-ams", provider: "Cloudflare", label: "Cloudflare Amsterdam PoP", city: "Amsterdam, Netherlands", lat: 52.37, lon: 4.9, source: "https://www.cloudflare.com/network/" },
  ];

  const state = { map: null, layers: null, initialized: false, failed: false, tracestrackLayer: null };

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
  const tracestrackApiKey = () => (typeof prefs !== "undefined" && prefs.tracestrackApiKey ? String(prefs.tracestrackApiKey).trim() : "");

  function renderDtcPins() {
    if (!state.layers) return;
    state.layers.dtc.clearLayers();
    DTC_LOCATIONS.forEach((dtc) => {
      const marker = L.marker([dtc.lat, dtc.lon], {
        icon: L.divIcon({
          className: "leaflet-dtc-marker",
          html: '<span></span>',
          iconSize: [14, 14],
        }),
        title: `${dtc.label} — ${dtc.city}`,
        alt: dtc.label,
        keyboard: true,
      });
      marker.bindPopup(
        `<strong>${escapeHtml(dtc.label)}</strong><br>${escapeHtml(dtc.city)}<br>` +
          `<a href="${escapeHtml(dtc.source)}" target="_blank" rel="noopener noreferrer">source</a>`
      );
      state.layers.dtc.addLayer(marker);
    });
  }

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

      // Issue #72: a real Leaflet layer control (native UI, top-right by
      // default) replaces the previous single hard-coded tile layer, built
      // from the LEAFLET_BASEMAPS registry above so more basemaps can be
      // added later without touching this function.
      const baseLayers = {};
      let defaultBaseLayer = null;
      Object.keys(LEAFLET_BASEMAPS).forEach((name) => {
        const def = LEAFLET_BASEMAPS[name];
        const layer = L.tileLayer(def.url, Object.assign({}, def.options));
        baseLayers[name] = layer;
        if (name === "OpenStreetMap Standard") defaultBaseLayer = layer;
        if (name === "Tracestrack Topo") state.tracestrackLayer = layer;
      });
      (defaultBaseLayer || baseLayers[Object.keys(baseLayers)[0]]).addTo(map);
      if (state.tracestrackLayer) state.tracestrackLayer.options.key = tracestrackApiKey();

      // Future-ready layer-group structure (Issue #69, extended by Issue
      // #72's DTC pins): countries/destinations are the two datasets that
      // already exist; dtc is a small additive, off-by-default overlay (not
      // added to the map here, so its layer-control checkbox starts
      // unchecked). Additional infrastructure datasets, if they are ever
      // added to the backend, can register another named L.layerGroup()
      // here the same way, without replacing the map engine.
      state.layers = {
        countries: L.layerGroup().addTo(map),
        destinations: L.layerGroup(),
        dtc: L.layerGroup(),
      };

      const overlayLayers = { "Data Centers (beta)": state.layers.dtc };
      L.control.layers(baseLayers, overlayLayers, { position: "topright", collapsed: true }).addTo(map);
      renderDtcPins();

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
  }

  function setVisibleLayer(mode) {
    if (!state.map || !state.layers) return;
    if (mode === "destinations") {
      if (!state.map.hasLayer(state.layers.destinations)) state.layers.destinations.addTo(state.map);
      if (state.map.hasLayer(state.layers.countries)) state.map.removeLayer(state.layers.countries);
    } else {
      if (!state.map.hasLayer(state.layers.countries)) state.layers.countries.addTo(state.map);
      if (state.map.hasLayer(state.layers.destinations)) state.map.removeLayer(state.layers.destinations);
    }
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
        zIndexOffset: selected ? 1000 : 0,
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
    return Array.from(cells.values()).map((b) => ({
      key: b.key,
      lat: b.sumLat / b.points.length,
      lon: b.sumLon / b.points.length,
      unique_ip_count: b.points.length,
      observation_count: b.observation_count,
      domain_count: b.domain_count,
      country_code: b.points[0].country_code,
      country_name: b.points[0].country_name,
      city: b.points.length === 1 ? b.points[0].city : null,
      sample_domains: Array.from(new Set(b.points.flatMap((p) => p.sample_domains || []))).slice(0, 5),
    }));
  }

  function renderDestinations(data, capabilities) {
    banner(null);
    clearLayers();
    setVisibleLayer("destinations");
    if (!capabilities || !capabilities.coordinates) {
      banner(
        "Coordinate-level destination data is unavailable &mdash; only a country GeoIP database is configured. Configure a city/coordinate-capable GeoIP database to enable Destinations mode, or switch to Countries. See docs/GEOIP.md."
      );
      renderMapDetail(null);
      return;
    }
    const points = (data?.destinations || []).filter((p) => p.lat != null && p.lon != null);
    if (!points.length) {
      banner(
        "No geolocated destination coordinates yet. This fills in as domains are queried and their actual DNS answers get matched against the configured city/coordinate GeoIP database."
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
      const label =
        c.unique_ip_count > 1
          ? `${num(c.unique_ip_count)} destinations: ${num(c.observation_count)} observations, ${num(c.domain_count)} domains`
          : `${c.city || c.country_name || c.country_code || "Unknown"}: ${num(c.observation_count)} observations, ${num(c.domain_count)} domains`;
      const marker = L.marker([c.lat, c.lon], {
        icon: bubbleIcon(size, color, selected),
        title: label,
        keyboard: true,
        zIndexOffset: selected ? 1000 : 0,
      });
      marker.on("click", () => activateCluster(c, data, capabilities));
      state.layers.destinations.addLayer(marker);
    });
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
    if (!provider.configured && !capabilities.coordinates) {
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

  /* Issue #72: called by the "Tracestrack API key" input's change handler in
   * the main inline <script> so pasting/editing a key updates the already-
   * created Tracestrack base layer in place (via Leaflet's own {key} URL-
   * template substitution) instead of requiring a reload. No-op if Leaflet
   * never initialized or Tracestrack isn't in LEAFLET_BASEMAPS. */
  window.mapUpdateTracestrackKey = function (key) {
    if (!state.tracestrackLayer) return;
    state.tracestrackLayer.options.key = key || "";
    state.tracestrackLayer.redraw();
  };

  /* Issue #72: called by a double-click on a country row in the breakdown
   * panel (app.py's renderMapBreakdown()) to additionally pan/zoom the real
   * Leaflet viewport to that country's centroid -- centerZoom alone (passed
   * on both single- and double-click, unchanged) only affects the legacy
   * SVG renderer's own mapZoom/mapViewCenter state, never this map. A
   * single click's selection/detail behavior is untouched; this only adds a
   * viewport move on top of it. */
  window.leafletFocusCountryOnMap = function (code) {
    if (!state.map || !mapLastPayload) return;
    const entity = (mapLastPayload.countries || []).find((c) => c.country_code === code);
    if (!entity || !entity.centroid) return;
    const [lat, lon] = entity.centroid;
    state.map.setView([lat, lon], Math.max(state.map.getZoom(), 5), { animate: !reducedMotion() });
  };
})();
