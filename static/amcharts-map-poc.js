/* DNS Inspector - amCharts 5 map experiment
 *
 * Opt-in renderer. Existing /api/analytics/map polling remains the network
 * owner; this file only replaces renderDestinationMap().
 *
 * Enable with AMCHARTS_MAP_ENABLED=1. Legacy SVG remains the default.
 */
(function () {
  "use strict";

  if (!window.am5 || !window.am5map || !window.am5geodata_worldLow) {
    console.warn("[dns-map-amcharts] libraries/geodata unavailable; keeping legacy renderer");
    return;
  }

  const AM5 = window.am5;
  const MAP = window.am5map;
  const host = document.getElementById("destination-map");
  if (!host) return;

  const state = {
    root: null,
    chart: null,
    countries: null,
    destinations: null,
    payload: null,
    selection: null,
    initialized: false
  };

  const num = value => Number.isFinite(Number(value)) ? Number(value) : 0;
  const mode = () =>
    (typeof prefs !== "undefined" && prefs.mapMode === "destinations")
      ? "destinations" : "countries";
  const reducedMotion = () =>
    !!((window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) ||
       document.documentElement.dataset.motion === "reduced" ||
       (typeof prefs !== "undefined" && prefs.reducedMotion));

  function themeColors() {
    const theme = typeof prefs !== "undefined" ? prefs.mapTheme : "cyan";
    if (theme === "indigo-gold") return { low: 0x294b72, high: 0xe0a52c, point: 0x58a6ff };
    if (theme === "bemo-accent") return { low: 0x254047, high: 0x2dd4c8, point: 0x2dd4c8 };
    return { low: 0x183c53, high: 0x37d6c5, point: 0x58a6ff };
  }

  function esc(value) {
    const el = document.createElement("div");
    el.textContent = value == null ? "" : String(value);
    return el.innerHTML;
  }

  function clearDetail() {
    const el = document.getElementById("destination-map-detail");
    if (!el) return;
    el.hidden = true;
    el.innerHTML = "";
  }

  function renderDetail(selection) {
    const el = document.getElementById("destination-map-detail");
    if (!el || !selection || !state.payload) return clearDetail();

    if (selection.type === "country") {
      const entity = (state.payload.countries || []).find(
        x => String(x.country_code || "").toUpperCase() === selection.countryCode
      );
      if (!entity) return clearDetail();

      const domains = (entity.sample_domains || []).map(v => '<span class="chip">' + esc(v) + "</span>").join("") ||
        '<span class="sub">No sampled domains</span>';
      const devices = (entity.sample_devices || []).map(v => '<span class="chip">' + esc(v) + "</span>").join("") ||
        '<span class="sub">No associated devices</span>";

      el.hidden = false;
      el.innerHTML =
        '<button type="button" class="map-detail-close" id="amcharts-detail-close" aria-label="Close map selection">&times;</button>' +
        '<h3>' + esc(entity.country_name || entity.country_code) + ' <span class="sub">' +
        esc(entity.country_code || "") + "</span></h3>" +
        '<div class="stats-note">' + num(entity.observation_count) + " observations · " +
        num(entity.domain_count) + " domains · " + num(entity.device_count) + " devices</div>" +
        '<div class="map-detail-row"><b>Domains</b><div class="chip-row">' + domains + "</div></div>" +
        '<div class="map-detail-row"><b>Devices</b><div class="chip-row">' + devices + "</div></div>";
    } else {
      const entity = (state.payload.destinations || []).find(
        x => String(x.ip || "") === selection.ip
      );
      if (!entity) return clearDetail();

      const domains = (entity.sample_domains || []).map(v => '<span class="chip">' + esc(v) + "</span>").join("") ||
        '<span class="sub">No sampled domains</span>';

      el.hidden = false;
      el.innerHTML =
        '<button type="button" class="map-detail-close" id="amcharts-detail-close" aria-label="Close map selection">&times;</button>' +
        '<h3>' + esc((entity.city ? entity.city + ", " : "") +
        (entity.country_name || entity.country_code || "Unknown")) +
        ' <span class="sub">' + esc(entity.ip || "") + "</span></h3>" +
        '<div class="stats-note">' + num(entity.observation_count) +
        " observations · " + num(entity.domain_count) + " domains</div>" +
        '<div class="map-detail-row"><b>Domains</b><div class="chip-row">' + domains + "</div></div>";
    }

    document.getElementById("amcharts-detail-close")?.addEventListener("click", () => {
      state.selection = null;
      clearDetail();
      syncSelection();
    });
  }

  function syncSelection() {
    if (!state.countries) return;
    const selected = String(state.selection?.countryCode || "").toUpperCase();

    state.countries.mapPolygons.each(polygon => {
      const id = String(polygon.dataItem?.get("id") || "").toUpperCase();
      const active = id === selected;
      polygon.set("stroke", active ? AM5.color(0xffffff) : AM5.color(0x334155));
      polygon.set("strokeWidth", active ? 2.3 : 0.6);
      polygon.set("fillOpacity", active ? 0.95 :
        (num(polygon.dataItem?.get("observation_count")) > 0 ? 0.78 : 0.28));
    });
  }

  function build() {
    if (state.initialized) return;

    host.innerHTML = "";
    host.classList.add("dns-inspector-amcharts-map");
    host.style.width = "100%";
    host.style.height = "min(62vw, 520px)";
    host.style.minHeight = "360px";
    host.style.border = "1px solid var(--border)";
    host.style.borderRadius = "var(--radius-md)";
    host.style.overflow = "hidden";
    host.style.background = "var(--surface-1)";

    state.root = AM5.Root.new(host);
    state.chart = state.root.container.children.push(
      MAP.MapChart.new(state.root, {
        projection: MAP.geoNaturalEarth1(),
        panX: "translateX",
        panY: "translateY",
        wheelY: "zoom",
        pinchZoom: !reducedMotion(),
        minZoomLevel: 1,
        maxZoomLevel: 24,
        zoomStep: 1.35,
        animationDuration: reducedMotion() ? 0 : 220,
        maxPanOut: 0.25
      })
    );

    const background = state.chart.series.unshift(MAP.MapPolygonSeries.new(state.root, {}));
    background.mapPolygons.template.setAll({
      fill: AM5.color(0x071018),
      fillOpacity: 1,
      strokeOpacity: 0,
      interactive: false
    });
    background.data.setAll([{ geometry: MAP.getGeoRectangle(85, 180, -85, -180) }]);

    state.countries = state.chart.series.push(MAP.MapPolygonSeries.new(state.root, {
      geoJSON: window.am5geodata_worldLow,
      valueField: "observation_count"
    }));
    state.countries.mapPolygons.template.setAll({
      fill: AM5.color(0x223344),
      fillOpacity: 0.28,
      stroke: AM5.color(0x334155),
      strokeWidth: 0.6,
      interactive: true
    });
    state.countries.mapPolygons.template.states.create("hover", {
      fill: AM5.color(0x58a6ff),
      fillOpacity: 0.95
    });

    const pointTemplate = AM5.Template.new({});
    state.destinations = state.chart.series.push(MAP.ClusteredPointSeries.new(state.root, {
      latitudeField: "lat",
      longitudeField: "lon",
      valueField: "observation_count",
      minDistance: 28,
      clusterDelay: reducedMotion() ? 0 : 40,
      stopClusterZoom: 0.92,
      clusteredBullet: root => {
        const c = AM5.Container.new(root, { cursorOverStyle: "pointer" });
        c.children.push(AM5.Circle.new(root, {
          radius: 12,
          fill: AM5.color(0xf2c14e),
          fillOpacity: 0.94,
          stroke: AM5.color(0xffffff),
          strokeOpacity: 0.45,
          strokeWidth: 1.5
        }));
        c.children.push(AM5.Label.new(root, {
          centerX: AM5.p50,
          centerY: AM5.p50,
          populateText: true,
          text: "{clusteredDataItems.length}",
          fill: AM5.color(0x071018),
          fontSize: 11,
          fontWeight: "700"
        }));
        c.events.on("click", ev => {
          const di = ev.target.dataItem;
          if (di) state.destinations.zoomToCluster(di);
        });
        return AM5.Bullet.new(root, { sprite: c });
      }
    }));

    state.destinations.bullets.push(root => {
      const circle = AM5.Circle.new(root, {
        radius: 5,
        fill: AM5.color(themeColors().point),
        fillOpacity: 0.9,
        stroke: AM5.color(0xffffff),
        strokeOpacity: 0.35,
        strokeWidth: 1,
        interactive: true
      }, pointTemplate);

      circle.events.on("click", ev => {
        const entity = ev.target.dataItem?.dataContext;
        if (!entity) return;
        state.selection = { type: "destination", ip: String(entity.ip) };
        renderDetail(state.selection);
      });

      return AM5.Bullet.new(root, { sprite: circle });
    });

    state.destinations.set("heatRules", [{
      target: pointTemplate,
      dataField: "observation_count",
      min: 4,
      max: 18,
      key: "radius"
    }, {
      target: pointTemplate,
      dataField: "observation_count",
      min: AM5.color(0x2bb673),
      max: AM5.color(0xe04b43),
      key: "fill"
    }]);

    state.countries.mapPolygons.template.events.on("click", ev => {
      const code = String(ev.target.dataItem?.get("id") || "").toUpperCase();
      if (!code) return;
      state.selection = { type: "country", countryCode: code };
      syncSelection();
      renderDetail(state.selection);
    });

    state.initialized = true;
    syncSelection();
  }

  function update(payload) {
    state.payload = payload || {};
    build();

    const colors = themeColors();

    state.countries.mapPolygons.template.setAll({ fill: AM5.color(colors.low) });
    state.countries.set("heatRules", [{
      target: state.countries.mapPolygons.template,
      dataField: "observation_count",
      min: AM5.color(colors.low),
      max: AM5.color(colors.high),
      key: "fill"
    }]);

    const countries = (state.payload.countries || []).map(x => ({
      id: String(x.country_code || "").toUpperCase(),
      name: x.country_name || x.country_code || "",
      observation_count: num(x.observation_count),
      domain_count: num(x.domain_count),
      device_count: num(x.device_count),
      unique_ip_count: num(x.unique_ip_count),
      sample_domains: x.sample_domains || [],
      sample_devices: x.sample_devices || []
    })).filter(x => x.id);
    state.countries.data.setAll(countries);

    const destinations = (state.payload.destinations || [])
      .filter(x => x && x.ip && Number.isFinite(Number(x.lat)) && Number.isFinite(Number(x.lon)))
      .map(x => ({
        ip: String(x.ip),
        country_code: String(x.country_code || "").toUpperCase(),
        country_name: x.country_name || "",
        city: x.city || "",
        lat: Number(x.lat),
        lon: Number(x.lon),
        observation_count: num(x.observation_count),
        domain_count: num(x.domain_count),
        sample_domains: x.sample_domains || []
      }));
    state.destinations.data.setAll(destinations);

    state.countries.set("visible", mode() === "countries");
    state.destinations.set("visible", mode() === "destinations");
    syncSelection();

    const subtitle = document.getElementById("destination-map-subtitle");
    if (subtitle) subtitle.textContent = mode() === "destinations"
      ? "amCharts vector map — observed destination IPs at GeoIP coordinates, clustered when close."
      : "amCharts vector map — country aggregates from the existing /api/analytics/map payload.";
  }

  function fit() {
    if (!state.chart) return;

    if (mode() === "destinations" && state.destinations.dataItems.length) {
      state.destinations.zoomToDataItems(state.destinations.dataItems);
      return;
    }
    const items = state.countries.dataItems.filter(item => num(item.get("observation_count")) > 0);
    if (items.length) state.countries.zoomToDataItems(items);
  }

  window.renderDestinationMap = update;

  // Paint immediately. The normal bounded map polling remains responsible for
  // subsequent refreshes and calls the renderer above.
  fetch("/api/analytics/map", { cache: "no-store" })
    .then(response => response.ok ? response.json() : null)
    .then(data => { if (data) update(data); })
    .catch(error => console.debug("[dns-map-amcharts] initial fetch failed", error));

  document.getElementById("map-mode-select")?.addEventListener("change", () => {
    if (state.payload) update(state.payload);
  });
  document.getElementById("map-theme-select")?.addEventListener("change", () => {
    if (state.payload) update(state.payload);
  });
  document.getElementById("map-zoom-in-btn")?.addEventListener("click", () => state.chart?.zoomIn());
  document.getElementById("map-zoom-out-btn")?.addEventListener("click", () => state.chart?.zoomOut());
  document.getElementById("map-fit-btn")?.addEventListener("click", fit);
  document.getElementById("map-reset-btn")?.addEventListener("click", () => {
    state.selection = null;
    clearDetail();
    state.chart?.goHome();
    syncSelection();
  });
})();
