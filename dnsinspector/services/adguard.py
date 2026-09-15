import dnsinspector.legacy_app as legacy

agh_login = legacy.agh_login
agh_get = legacy.agh_get
fetch_querylog = legacy.fetch_querylog
adguard_current_status = legacy.adguard_current_status
cached_adguard_status = legacy.cached_adguard_status
refresh_adguard_status = legacy.refresh_adguard_status
_schedule_adguard_status = legacy.schedule_adguard_status if hasattr(legacy, 'schedule_adguard_status') else legacy._schedule_adguard_status
fetch_clients = legacy.fetch_clients
_adguard_list_test = legacy._adguard_list_test
_adguard_explain = legacy._adguard_explain
_adguard_explain_card = legacy._adguard_explain_card
