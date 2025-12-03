import logging

from spaceone.inventory.plugin.collector.lib import *

from plugin.conf.cloud_service_conf import ICON_URL
from plugin.connector.functions.functions_connector import FunctionsConnector
from plugin.connector.subscriptions.subscriptions_connector import (
    SubscriptionsConnector,
)
from plugin.manager.base import AzureBaseManager

_LOGGER = logging.getLogger("spaceone")


class FunctionsManager(AzureBaseManager):
    cloud_service_group = "Functions"
    cloud_service_type = "Instance"
    service_code = "/Microsoft.Web/sites"

    def create_cloud_service_type(self):
        return make_cloud_service_type(
            name=self.cloud_service_type,
            group=self.cloud_service_group,
            provider=self.provider,
            service_code=self.service_code,
            metadata_path=self.get_metadata_path(),
            is_primary=True,
            is_major=True,
            labels=["Serverless"],
            tags={
                "spaceone:icon": f"{ICON_URL}/azure-functions.svg",
            },
        )

    def create_cloud_service(self, options, secret_data, schema):
        cloud_services = []
        error_responses = []

        functions_conn = FunctionsConnector(secret_data=secret_data)
        subscription_conn = SubscriptionsConnector(secret_data=secret_data)

        # 구독 정보 가져오기
        subscription_obj = subscription_conn.get_subscription(
            secret_data["subscription_id"]
        )
        subscription_info = self.convert_nested_dictionary(subscription_obj)

        try:
            function_app_list = functions_conn.list_function_apps()
        except Exception as e:
            _LOGGER.error(
                f"[FunctionsManager.create_cloud_service] list_function_apps error: {e}",
                exc_info=True,
            )
            error_responses.append(
                make_error_response(
                    error=e,
                    provider=self.provider,
                    cloud_service_group=self.cloud_service_group,
                    cloud_service_type=self.cloud_service_type,
                )
            )
            return cloud_services, error_responses

        for function_app in function_app_list:
            try:
                fa_dict = self.convert_nested_dictionary(function_app)
                resource_id = fa_dict.get("id")

                # 리소스 그룹, 위치 등 기본 값
                resource_group = self.get_resource_group_from_id(resource_id)
                location = (fa_dict.get("location") or "").replace(" ", "").lower()
                fa_dict["location"] = location

                # --- 1) Function App 상세 조회 (state, serverFarmId, 네트워크 속성 등) ---
                site_detail = functions_conn.get_function_app_detail(resource_id) or {}
                site_props = (site_detail.get("properties") or {})

                status = site_props.get("state")
                server_farm_id = site_props.get("serverFarmId")

                fa_dict["properties"] = site_props
                fa_dict["status"] = status
                fa_dict["server_farm_id"] = server_farm_id

                # --- 2) App Service Plan 상세 조회 (pricing tier, plan name 등) ---
                plan_detail = {}
                if server_farm_id:
                    plan_detail = (
                        functions_conn.get_app_service_plan_detail(server_farm_id)
                        or {}
                    )

                plan_sku = (plan_detail.get("sku") or {})
                plan_props = (plan_detail.get("properties") or {})

                # sku.name: "Y1", "S1" ...
                # sku.tier: "Dynamic", "Standard" ...
                sku_name = plan_sku.get("name")
                sku_tier = plan_sku.get("tier")

                # 리스트/검색용 Pricing Tier (계층 이름 위주)
                pricing_tier = sku_tier or sku_name
                plan_name = plan_detail.get("name") or (
                    server_farm_id.split("/")[-1] if server_farm_id else None
                )

                # Pricing tier / sku 는 항상 필드로 둔다
                fa_dict["pricing_tier"] = pricing_tier
                fa_dict["sku"] = plan_sku

                # App Service Plan 정보
                plan_rg = (
                    self.get_resource_group_from_id(server_farm_id)
                    if server_farm_id
                    else None
                )
                plan_location = plan_detail.get("location") or location

                # 인스턴스 수 (numberOfWorkers나 capacity 중 환경에 맞는 쪽 선택)
                instance_count = plan_props.get("numberOfWorkers")
                if instance_count is None:
                    instance_count = plan_props.get("capacity")

                # 앱 수
                apps_count = plan_props.get("numberOfSites")

                # OS는 reserved 플래그로 판별 (True=Linux, False=Windows)
                reserved = plan_props.get("reserved")
                if reserved is True:
                    operating_system = "Linux"
                elif reserved is False:
                    operating_system = "Windows"
                else:
                    operating_system = None

                # Zone redundant: bool을 포털처럼 문자열로 변환
                zone_flag = plan_props.get("zoneRedundant")
                if zone_flag is True:
                    zone_redundant = "Enabled"
                elif zone_flag is False:
                    zone_redundant = "Disabled"
                else:
                    zone_redundant = "Not configured"

                fa_dict["app_service_plan"] = {
                    "id": server_farm_id,
                    "name": plan_name,
                    "resource_group": plan_rg,
                    "location": plan_location,
                    "pricing_plan": sku_name or sku_tier,
                    "instance_count": instance_count,
                    "apps": apps_count,
                    "operating_system": operating_system,
                    "zone_redundant": zone_redundant,
                }

                # --- 3) Networking 정보 구성 ---
                # raw 값 먼저 수집
                networking_raw = {
                    "public_network_access": site_props.get("publicNetworkAccess"),
                    "app_assigned_address": site_props.get("inboundIpAddress"),
                    "private_endpoints": [],
                    "inbound_addresses": [],
                    "virtual_network_subnet_id": site_props.get("virtualNetworkSubnetId"),
                    "hybrid_connections": [],
                    "outbound_dns": None,
                    "outbound_addresses": [],
                    "nat_gateway": None,
                    "network_security_group": None,
                    "user_defined_route": None,
                }

                # 3-1) Private endpoints (raw)
                try:
                    pe_list = functions_conn.list_private_endpoint_connections(
                        resource_group, fa_dict.get("name")
                    )
                    for pe in pe_list or []:
                        pe_props = (pe.get("properties") or {})
                        networking_raw["private_endpoints"].append(
                            {
                                "name": pe.get("name"),
                                "ip_addresses": pe_props.get("ipAddresses"),
                                "private_endpoint_id": (
                                    pe_props.get("privateEndpoint") or {}
                                ).get("id"),
                                "status": (
                                    pe_props.get("privateLinkServiceConnectionState")
                                    or {}
                                ).get("status"),
                            }
                        )
                except Exception as pe_e:
                    _LOGGER.warning(
                        f"[FunctionsManager.create_cloud_service] "
                        f"list_private_endpoint_connections error: {pe_e}",
                        exc_info=True,
                    )

                # 3-2) Inbound addresses (raw)
                inbound_ip = networking_raw.get("app_assigned_address")
                if inbound_ip:
                    networking_raw["inbound_addresses"].append(inbound_ip)

                for pe in networking_raw["private_endpoints"]:
                    for ip in pe.get("ip_addresses") or []:
                        if ip:
                            networking_raw["inbound_addresses"].append(ip)

                # 3-3) Outbound addresses (raw)
                for raw_ips in [
                    site_props.get("outboundIpAddresses"),
                    site_props.get("possibleOutboundIpAddresses"),
                ]:
                    if raw_ips:
                        networking_raw["outbound_addresses"].extend(
                            [ip.strip() for ip in raw_ips.split(",") if ip.strip()]
                        )

                # 3-4) VNet 통합 + NAT/NSG/UDR + Outbound DNS (raw)
                subnet_id = networking_raw["virtual_network_subnet_id"]
                if subnet_id:
                    try:
                        subnet = functions_conn.get_subnet(subnet_id) or {}
                        subnet_props = (subnet.get("properties") or {})

                        networking_raw["nat_gateway"] = (
                            (subnet_props.get("natGateway") or {}).get("id")
                        )
                        networking_raw["network_security_group"] = (
                            (subnet_props.get("networkSecurityGroup") or {}).get("id")
                        )
                        networking_raw["user_defined_route"] = (
                            (subnet_props.get("routeTable") or {}).get("id")
                        )

                        # VNet DNS
                        vnet_id = subnet_id.split("/subnets/")[0]
                        vnet = functions_conn.get_virtual_network(vnet_id) or {}
                        vnet_props = (vnet.get("properties") or {})
                        dhcp = (vnet_props.get("dhcpOptions") or {})
                        dns_servers = dhcp.get("dnsServers")

                        if dns_servers:
                            networking_raw["outbound_dns"] = ", ".join(dns_servers)
                        else:
                            networking_raw["outbound_dns"] = "Default (Azure-provided)"
                    except Exception as net_e:
                        _LOGGER.warning(
                            f"[FunctionsManager.create_cloud_service] "
                            f"networking(vnet/subnet) error: {net_e}",
                            exc_info=True,
                        )
                        if networking_raw["outbound_dns"] is None:
                            networking_raw["outbound_dns"] = "Default (Azure-provided)"
                else:
                    # VNet 통합이 없으면 Azure 기본 DNS
                    networking_raw["outbound_dns"] = "Default (Azure-provided)"

                # 3-5) Hybrid connections (raw)
                try:
                    hc_list = functions_conn.list_hybrid_connections(
                        resource_group, fa_dict.get("name")
                    )
                    for hc in hc_list or []:
                        hc_props = (hc.get("properties") or {})
                        networking_raw["hybrid_connections"].append(
                            {
                                "name": hc.get("name"),
                                "hostname": hc_props.get("hostname"),
                                "port": hc_props.get("port"),
                                "service_bus_namespace": hc_props.get(
                                    "serviceBusNamespace"
                                ),
                                "relay_name": hc_props.get("relayName"),
                            }
                        )
                except Exception as hc_e:
                    _LOGGER.warning(
                        f"[FunctionsManager.create_cloud_service] "
                        f"list_hybrid_connections error: {hc_e}",
                        exc_info=True,
                    )

                # --- 3-6) Azure 포털 느낌으로 UI용 문자열 만들기 ---
                # 플랜 타입에 따라 지원 여부 판단
                sku_name_upper = (sku_name or "").upper()
                tier_upper = (pricing_tier or "").upper()
                is_consumption_plan = (
                    sku_name_upper == "Y1" or tier_upper == "DYNAMIC"
                )

                networking = {}

                # Public network access
                pna = networking_raw["public_network_access"]
                if pna is None:
                    networking["public_network_access"] = "Not configured"
                elif str(pna).lower() == "enabled":
                    networking["public_network_access"] = "Enabled (default behavior)"
                elif str(pna).lower() == "disabled":
                    networking["public_network_access"] = "Disabled"
                else:
                    networking["public_network_access"] = str(pna)

                # App assigned address
                if networking_raw["app_assigned_address"]:
                    networking["app_assigned_address"] = (
                        networking_raw["app_assigned_address"]
                    )
                else:
                    networking["app_assigned_address"] = "Not configured"

                # Private endpoints
                if networking_raw["private_endpoints"]:
                    names = [
                        pe.get("name")
                        for pe in networking_raw["private_endpoints"]
                        if pe.get("name")
                    ]
                    if names:
                        networking["private_endpoints"] = ", ".join(names)
                    else:
                        networking["private_endpoints"] = (
                            f"{len(networking_raw['private_endpoints'])} endpoint(s)"
                        )
                else:
                    networking["private_endpoints"] = (
                        "Not supported" if is_consumption_plan else "Not configured"
                    )

                # Inbound addresses
                if networking_raw["inbound_addresses"]:
                    uniq = sorted(set(networking_raw["inbound_addresses"]))
                    networking["inbound_addresses"] = ", ".join(uniq)
                else:
                    # 포털처럼 주소 목록이 없으면 Dynamic으로 표기
                    networking["inbound_addresses"] = "Dynamic"

                # Virtual network integration
                if subnet_id:
                    subnet_name = subnet_id.split("/subnets/")[-1]
                    networking["virtual_network_integration"] = subnet_name
                else:
                    networking["virtual_network_integration"] = (
                        "Not supported" if is_consumption_plan else "Not configured"
                    )

                # Hybrid connections
                if networking_raw["hybrid_connections"]:
                    names = [
                        hc.get("name")
                        for hc in networking_raw["hybrid_connections"]
                        if hc.get("name")
                    ]
                    networking["hybrid_connections"] = (
                        ", ".join(names) if names else "Configured"
                    )
                else:
                    networking["hybrid_connections"] = (
                        "Not supported" if is_consumption_plan else "Not configured"
                    )

                # Outbound DNS
                networking["outbound_dns"] = (
                    networking_raw["outbound_dns"] or "Default (Azure-provided)"
                )

                # Outbound addresses
                if networking_raw["outbound_addresses"]:
                    uniq = sorted(set(networking_raw["outbound_addresses"]))
                    networking["outbound_addresses"] = ", ".join(uniq)
                else:
                    networking["outbound_addresses"] = "Dynamic"

                # NAT / NSG / UDR : VNet이 없으면 N/A, 있으면 Not configured 또는 리소스 ID
                if subnet_id:
                    networking["nat_gateway"] = (
                        networking_raw["nat_gateway"] or "Not configured"
                    )
                    networking["network_security_group"] = (
                        networking_raw["network_security_group"]
                        or "Not configured"
                    )
                    networking["user_defined_route"] = (
                        networking_raw["user_defined_route"] or "Not configured"
                    )
                else:
                    networking["nat_gateway"] = "N/A"
                    networking["network_security_group"] = "N/A"
                    networking["user_defined_route"] = "N/A"

                # raw / display 둘 다 보존
                fa_dict["networking_raw"] = networking_raw
                fa_dict["networking"] = networking

                # --- 공통 메타 정보 ---
                fa_dict = self.update_tenant_id_from_secret_data(fa_dict, secret_data)
                fa_dict.update(
                    {
                        "resource_group": resource_group,
                        "subscription_id": subscription_info["subscription_id"],
                        "subscription_name": subscription_info["display_name"],
                        "azure_monitor": {"resource_id": resource_id},
                    }
                )

                self.set_region_code(location)

                # instance_type 계산
                sku = plan_sku or {}
                instance_type = (
                    sku.get("name") or fa_dict.get("server_farm_id") or "UNKNOWN"
                )

                cloud_services.append(
                    make_cloud_service(
                        name=fa_dict.get("name"),
                        cloud_service_type=self.cloud_service_type,
                        cloud_service_group=self.cloud_service_group,
                        provider=self.provider,
                        data=fa_dict,
                        account=secret_data["subscription_id"],
                        instance_type=instance_type,
                        region_code=location,
                        reference=self.make_reference(resource_id),
                        tags=fa_dict.get("tags", {}),
                        data_format="dict",
                    )
                )

            except Exception as e:
                _LOGGER.error(
                    f"[FunctionsManager.create_cloud_service] Error {e}",
                    exc_info=True,
                )
                error_responses.append(
                    make_error_response(
                        error=e,
                        provider=self.provider,
                        cloud_service_group=self.cloud_service_group,
                        cloud_service_type=self.cloud_service_type,
                    )
                )

        return cloud_services, error_responses
