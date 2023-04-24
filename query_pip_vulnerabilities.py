"""Simple script to query GitHub's GraphQL API for vulnerable PIP packages."""

import asyncio
import logging
import operator
import shutil
import sys
from pathlib import Path
from string import Template
from tempfile import TemporaryDirectory
from typing import Any, Dict, Final, Iterable, List, Optional, Tuple, Union

import aiohttp
import pkg_resources

from lib.pipcompile import pipcompile
from packaging.version import LegacyVersion, Version, parse

_GITHUB_ACCESS_TOKEN = ""
_TMP_DIRECTORY: Final = TemporaryDirectory()
_REQUIREMENTS_INS_ORIGINAL: Final = [Path("./example/requirements.in")]
_REQUIREMENTS_TXT_ORIGINAL: Final = Path("./example/requirements.txt")
_REQUIREMENTS_INS_COPY: Final = [
    Path(_TMP_DIRECTORY.name) / input_file for input_file in _REQUIREMENTS_INS_ORIGINAL
]
_REQUIREMENTS_TXT_COPY: Final = Path(_TMP_DIRECTORY.name) / _REQUIREMENTS_TXT_ORIGINAL
_GRAPHQL_API_URL: Final = "https://api.github.com/graphql"
_NUMBER_OF_RESULTS: Final = 100
_ECOSYSTEM: Final = "PIP"
_LOG_FORMAT: Final = (
    "[%(asctime)s.%(msecs)03d] %(filename)s:%(lineno)d: %(levelname)s: %(message)s"
)

_OPERATOR_LOOKUP_TABLE: Final = {
    "<": operator.lt,
    "<=": operator.le,
    "=": operator.eq,
    ">": operator.gt,
    ">=": operator.ge,
}

# GraphQL limitations as of July 2022:
# The API doesn't provide a way to filter by affected software versions (we need to query all versions all at once and filter manually)
# There's no possibility to query for specific software names (only package names that are part of an ecosystem are supported)
_VULNERABILITIES_QUERY_TEMPLATE: Final = Template(
    """
{
  securityVulnerabilities(first: $first, ecosystem: $ecosystem, package: "$package") {
    nodes {
      severity
      vulnerableVersionRange
      advisory {
        ghsaId
      }
    }
  }
}
"""
)

_LOGGER: Final = logging.getLogger(__name__)


def _compile_requirements(
    *,
    input_files: Iterable[Path],
    output_file: Optional[Path] = None,
) -> bool:
    """Compiles requirements.in files into a requirements.txt file.

    Args:
        input_files: Input files that we want to compile with pip-compile.
        output_file: Output file that we want to create or update with pip-compile.

    Returns:
        True: input_files were compiled succesfully.
        False: Otherwise.
    """
    pipcompile_args = [
        "--allow-unsafe",
        "--no-emit-index-url",
        "--no-annotate",
        "--no-header",
        "--quiet",
    ]

    if not all(input_file.exists() for input_file in iter(input_files)):
        return False

    result = pipcompile(
        input_files=input_files,
        output_file=output_file,
        optional_args=pipcompile_args,
    )

    if result == 0:
        return True
    else:
        return False


def _parse_requirements_txt(requirements_txt_file: Path) -> Dict[str, str]:
    """Parses a requirements.txt file to get a list of PIP packages.

    Args:
        requirements__txt_file: The path to the requirements.txt file.

    Returns:
        Dictionary of PIP packages.
    """
    pip_packages = dict()

    with Path(requirements_txt_file).open() as requirements_txt:
        for requirement in pkg_resources.parse_requirements(requirements_txt):
            name = requirement.project_name
            specs = requirement.specs

            # https://setuptools.pypa.io/en/latest/pkg_resources.html#requirement-methods-and-attributes
            if (
                not name
                or not specs
                or len(specs) > 1
                or not specs[0]
                or len(specs[0]) != 2
                or not specs[0][1]
            ):
                _LOGGER.warning(
                    "Could not parse PIP requirement: %s. Skipping...", requirement
                )
                continue
            else:
                version = specs[0][1]

            pip_packages[name] = version

    return pip_packages


def _format_query_response(
    response: Dict[str, Any], pip_package_name: str
) -> List[Dict[str, str]]:
    """Converts a GraphQL response into a simple dictionary.

    Args:
        response: The GraphQL response we want to parse.
        pip_package_name: Used to replace all pip package names with the ones from the original requirements.txt file.

    Returns:
        A list of dictionaries that store vulnerabilities.
    """
    return [
        {
            "name": pip_package_name,
            "severity": node["severity"],
            "vulnerableVersionRange": node["vulnerableVersionRange"],
            "advisory": node["advisory"],
        }
        for node in response["data"]["securityVulnerabilities"]["nodes"]
    ]


async def _run_query_async(
    session: aiohttp.ClientSession,
    query: str,
    headers: Dict[str, str],
    pip_package_name: str,
) -> List[Dict[str, str]]:
    """Runs GraphQL queries against https://api.github.com/graphql to get a list of known CVEs.

    Args:
        session: The aiohttp session used to send our queries.
        query: The actual query string.
        headers: HTTP header that contains the Github access token.
        pip_package_name: Package name used for query formatting.

    Returns:
        A list of dictionaries that store vulnerabilities.
    """
    async with session.post(
        _GRAPHQL_API_URL, json={"query": query}, headers=headers
    ) as response:
        response_json = await response.json()
        if response_json:
            return _format_query_response(response_json, pip_package_name)
        else:
            return []


def _parse_affected_version_range(
    version_range: str,
) -> List[Tuple[str, Union[LegacyVersion, Version]]]:
    """Parses a version range from a GraphQL response.

    Args:
        version_range: Input version range that comes in two formats (e.g., '< 9.0.1' or '>= 6.0.0, < 6.4.1').

    Returns:
        A list of tuples of a comparison operator and a version.
    """
    parsed_version_range: List[Tuple[str, Union[LegacyVersion, Version]]] = []
    version_range_pair = version_range.split(",")

    if not version_range_pair or len(version_range_pair) > 2:
        _LOGGER.error("Unsupported version range: %s.", version_range_pair)
        return parsed_version_range

    # Parse the lower bound comparison operator and version string
    lower_bound_operator_version = version_range_pair[0]

    if not lower_bound_operator_version:
        _LOGGER.error(
            "There is no lower bound comparison operator and version. Version range: %s",
            version_range_pair,
        )
        return parsed_version_range

    lower_bound_operator, lower_bound_version = lower_bound_operator_version.split(" ")
    parsed_lower_bound_version = parse(lower_bound_version)

    if (
        not lower_bound_operator
        or not lower_bound_version
        or not parsed_lower_bound_version
    ):
        _LOGGER.error(
            "Error parsing lower bound comparison operator and version. Operator: %s. Version: %s. Parsed version: %s.",
            lower_bound_operator,
            lower_bound_version,
            parsed_lower_bound_version,
        )
        return parsed_version_range

    if len(version_range_pair) == 1:
        parsed_version_range = [(lower_bound_operator, parsed_lower_bound_version)]
        return parsed_version_range

    # Parse the upper bound comparison operator and version string
    upper_bound_operator_version = version_range_pair[1].lstrip()

    if not upper_bound_operator_version:
        _LOGGER.error(
            "There is no upper bound comparison operator or version. Version range: %s",
            version_range_pair,
        )
        return parsed_version_range

    upper_bound_operator, upper_bound_version = upper_bound_operator_version.split(" ")
    parsed_upper_bound_version = parse(upper_bound_version)

    if (
        not upper_bound_operator
        or not upper_bound_version
        or not parsed_upper_bound_version
    ):
        _LOGGER.error(
            "Error parsing upper bound comparison operator and version. Operator: %s. Version: %s. Parsed version: %s.",
            upper_bound_operator,
            upper_bound_version,
            parsed_upper_bound_version,
        )
        return parsed_version_range

    parsed_version_range = [
        (lower_bound_operator, parsed_lower_bound_version),
        (upper_bound_operator, parsed_upper_bound_version),
    ]

    return parsed_version_range


def _check_if_affected(
    package_name: str,
    installed_pip_package_version: str,
    affected_pip_package_version_range: List[Tuple[str, Union[LegacyVersion, Version]]],
) -> bool:
    """Checks if PIP packages installed via the requirements.txt file are vulnerable.

    Args:
        package_name: The PIP package name.
        installed_pip_package_version: The currently installed PIP package version.
        affected_pip_package_version_range: The affected version range.

    Returns:
        True: Installed PIP package is affected.
        False: Installed PIP package is not affected.
    """
    parsed_pip_package_version = parse(installed_pip_package_version)

    if not parsed_pip_package_version or not affected_pip_package_version_range:
        raise RuntimeError(
            f"There's no version information for package {package_name}. Installed version: {parsed_pip_package_version}. Affected version range: {affected_pip_package_version_range}."
        )

    if len(affected_pip_package_version_range) == 1:
        lower_bound_operator, lower_bound_version = affected_pip_package_version_range[
            0
        ]
    elif len(affected_pip_package_version_range) == 2:
        lower_bound_operator, lower_bound_version = affected_pip_package_version_range[
            0
        ]
        upper_bound_operator, upper_bound_version = affected_pip_package_version_range[
            1
        ]
    else:
        raise RuntimeError(f"Unsupported version range for package {package_name}.")

    lower_bound_match = _OPERATOR_LOOKUP_TABLE[lower_bound_operator](
        parsed_pip_package_version, lower_bound_version
    )

    if len(affected_pip_package_version_range) == 1 and lower_bound_match:
        return True
    elif len(affected_pip_package_version_range) == 1 and not lower_bound_match:
        _LOGGER.debug(
            "%s is not affected! Installed version: %s. Vulnerable version range: %s.",
            package_name,
            installed_pip_package_version,
            affected_pip_package_version_range,
        )
        return False

    upper_bound_match = _OPERATOR_LOOKUP_TABLE[upper_bound_operator](
        parsed_pip_package_version, upper_bound_version
    )

    if lower_bound_match and upper_bound_match:
        return True

    return False


async def main() -> None:
    """Entry point for query_pip_vulnerabilities."""
    pip_packages = _parse_requirements_txt(_REQUIREMENTS_TXT_COPY)
    github_token = _GITHUB_ACCESS_TOKEN
    headers = {"Authorization": f"bearer {github_token}"}

    # Query GraphQL API for known CVEs
    async with aiohttp.ClientSession() as session:
        async_tasks = []
        for pip_package in pip_packages:
            query = _VULNERABILITIES_QUERY_TEMPLATE.substitute(
                first=_NUMBER_OF_RESULTS, ecosystem=_ECOSYSTEM, package=pip_package
            )
            async_tasks.append(
                asyncio.ensure_future(
                    _run_query_async(session, query, headers, pip_package)
                )
            )

        query_responses = await asyncio.gather(*async_tasks)

    # Search for vulnerable PIP packages
    for response in query_responses:
        if response:
            for security_vulnerability in response:
                package_name = security_vulnerability["name"]
                installed_pip_package_version = pip_packages[package_name]
                version_range = security_vulnerability["vulnerableVersionRange"]

                if not installed_pip_package_version or not version_range:
                    raise RuntimeError(
                        f"Could not parse installed version or affected version range of package {package_name}."
                    )

                affected_pip_package_version_range = _parse_affected_version_range(
                    version_range
                )
                is_affected = _check_if_affected(
                    package_name,
                    installed_pip_package_version,
                    affected_pip_package_version_range,
                )

                if is_affected:
                    severity = security_vulnerability["severity"]
                    advisory_id = security_vulnerability["advisory"]["ghsaId"]
                    _LOGGER.info(
                        "%s is vulnerable! Installed version: %s. Vulnerable versions: %s. Severity: %s, Advisory ID: %s.",
                        package_name,
                        installed_pip_package_version,
                        version_range,
                        severity,
                        advisory_id,
                    )


def copy_requirements() -> None:
    """Make a temporary copy of the requirements files.

    This is a workaround to force pip-compile to not upgrade transitive dependencies. Otherwise, there will be
    a lot of errors about incompatible versions in resolved dependencies.
    See https://github.com/jazzband/pip-tools/#updating-requirements
    pip-compile is used to compile requirements.in files into a requirements.txt file.
    """
    is_compiled = False

    for src, dst in zip(
        _REQUIREMENTS_INS_ORIGINAL + [_REQUIREMENTS_TXT_ORIGINAL],
        _REQUIREMENTS_INS_COPY + [_REQUIREMENTS_TXT_COPY],
    ):
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
    is_compiled = _compile_requirements(
        input_files=_REQUIREMENTS_INS_COPY,
        output_file=_REQUIREMENTS_TXT_COPY,
    )

    if not is_compiled:
        raise RuntimeError(
            f"Could not compile {_REQUIREMENTS_TXT_COPY} from {_REQUIREMENTS_INS_COPY}."
        )


if __name__ == "__main__":
    if not _GITHUB_ACCESS_TOKEN:
        sys.exit("Please specify your Github Access Token.")

    copy_requirements()

    # The force=True is needed to overcome an unconditional call to logging.basicConfig() that happens when
    # piptools.scripts.compile gets imported by lib.pipcompile.
    logging.basicConfig(
        level=logging.INFO,
        format=_LOG_FORMAT,
        datefmt="%H:%M:%S",
        stream=sys.stdout,
        force=True,
    )

    asyncio.run(main())
