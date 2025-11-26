import logging

from plugin.connector.base import AzureBaseConnector

_LOGGER = logging.getLogger("spaceone")


class ContainerRegistriesConnector(AzureBaseConnector):
    """
    Azure Container Registry 리소스를 조회하기 위한 클래스
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # 부모 클래스의 set_connect를 통해 container_registry_client가 초기화됩니다.
        self.set_connect(kwargs.get("secret_data"))

    def list_registries(self):
        """
        구독의 모든 레지스트리 목록 조회

        Returns:
            Iterator: 레지스트리 객체들의 이터레이터
        """
        return self.container_registry_client.registries.list()

    def get_registry(self, resource_group_name, registry_name):
        """
        특정 레지스트리의 상세 정보 조회

        Args:
            resource_group_name (str): 리소스 그룹 이름
            registry_name (str): 레지스트리 이름

        Returns:
            Registry: 레지스트리 객체
        """
        return self.container_registry_client.registries.get(
            resource_group_name=resource_group_name, registry_name=registry_name
        )

    def list_webhooks(self, resource_group_name, registry_name):
        """
        웹훅 목록 조회
        """
        try:
            return self.container_registry_client.webhooks.list(
                resource_group_name=resource_group_name, registry_name=registry_name
            )
        except Exception as e:
            _LOGGER.error(f"[list_webhooks] Error: {e}")
            return []

    def list_replications(self, resource_group_name, registry_name):
        """
        복제 정보 목록 조회
        """
        try:
            return self.container_registry_client.replications.list(
                resource_group_name=resource_group_name, registry_name=registry_name
            )
        except Exception as e:
            _LOGGER.error(f"[list_replications] Error: {e}")
            return []

    def list_usages(self, resource_group_name, registry_name):
        """
        사용량 정보 조회
        """
        try:
            return self.container_registry_client.registries.list_usages(
                resource_group_name=resource_group_name, registry_name=registry_name
            )
        except Exception as e:
            _LOGGER.error(f"[list_usages] Error: {e}")
            return None

    def list_tokens(self, resource_group_name, registry_name):
        """
        리포지토리 권한을 위한 토큰 조회
        """
        try:
            tokens_ops = getattr(self.container_registry_client, "tokens", None)
            if tokens_ops:
                return tokens_ops.list(
                    resource_group_name=resource_group_name, registry_name=registry_name
                )
        except Exception as e:
            _LOGGER.error(f"[list_tokens] Error: {e}")
        return []

    def list_scope_maps(self, resource_group_name, registry_name):
        """
        리포지토리 권한을 위한 범위 맵 조회
        """
        try:
            scope_maps_ops = getattr(self.container_registry_client, "scope_maps", None)
            if scope_maps_ops:
                return scope_maps_ops.list(
                    resource_group_name=resource_group_name, registry_name=registry_name
                )
        except Exception as e:
            _LOGGER.error(f"[list_scope_maps] Error: {e}")
        return []

    def list_cache_rules(self, resource_group_name, registry_name):
        """
        캐시 규칙 조회
        """
        try:
            cache_rules_ops = getattr(
                self.container_registry_client, "cache_rules", None
            )
            if cache_rules_ops:
                return cache_rules_ops.list(
                    resource_group_name=resource_group_name, registry_name=registry_name
                )
        except Exception as e:
            _LOGGER.error(f"[list_cache_rules] Error: {e}")
        return []

    def list_connected_registries(self, resource_group_name, registry_name):
        """
        연결된 레지스트리 조회
        """
        try:
            connected_ops = getattr(
                self.container_registry_client, "connected_registries", None
            )
            if connected_ops:
                return connected_ops.list(
                    resource_group_name=resource_group_name, registry_name=registry_name
                )
        except Exception as e:
            _LOGGER.error(f"[list_connected_registries] Error: {e}")
        return []

    def list_tasks(self, resource_group_name, registry_name):
        """
        작업 조회
        """
        try:
            tasks_ops = getattr(self.container_registry_client, "tasks", None)
            if tasks_ops:
                return tasks_ops.list(
                    resource_group_name=resource_group_name, registry_name=registry_name
                )
        except Exception as e:
            _LOGGER.error(f"[list_tasks] Error: {e}")
        return []
