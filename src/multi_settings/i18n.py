from __future__ import annotations

import os
import tempfile
from pathlib import Path

from multi_settings.config import user_config_dir

DEFAULT_LANGUAGE = "sv"
SUPPORTED_LANGUAGES = frozenset(("sv", "en"))

_SWEDISH: dict[str, str] = {
    "Overview": "Översikt",
    "Hardening": "Härdning",
    "Users": "Användare",
    "Switch to English": "Byt till engelska",
    "Switch to Swedish": "Byt till svenska",
    "Wait for the hardening operation to finish before changing language.": "Vänta tills härdningen är klar innan du byter språk.",
    "Least-privilege design": "Design med minsta behörighet",
    "Discovery stays in this ordinary-user process. System changes use the desktop's administrator authentication window; one authorization is normally retained for five minutes.": "Inventering sker i den här processen som körs som vanlig användare. Systemändringar använder skrivbordets fönster för administratörsautentisering; en auktorisering behålls normalt i fem minuter.",
    "Installed privileged helper": "Installerad privilegierad hjälpprocess",
    "PolicyKit client": "PolicyKit-klient",
    "YubiKey Manager": "YubiKey-hanterare",
    "PAM U2F enrollment": "PAM U2F-registrering",
    "Ready": "Klar",
    "Not found": "Hittades inte",
    "Order of execution": "Körordning",
    "Import custom-settings.yml, run an audit, review the results, and apply hardening.": "Importera custom-settings.yml, kör en granskning, kontrollera resultatet och tillämpa härdningen.",
    "Create and verify the administrator and standard accounts.": "Skapa och verifiera administratörskonton och standardkonton.",
    "Enroll primary and secondary YubiKeys, then enable login and sudo requirements.": "Registrera primära och sekundära YubiKeys och aktivera sedan kraven för inloggning och sudo.",
    "Create Ubuntu accounts without running the application as root.": "Skapa Ubuntu-konton utan att köra programmet som root.",
    "Interactive accounts": "Interaktiva konton",
    "Create account": "Skapa konto",
    "The account password is sent only to the local root helper over its private standard input.": "Kontolösenordet skickas endast till den lokala root-hjälpprocessen via dess privata standardindata.",
    "username": "användarnamn",
    "Full name": "Fullständigt namn",
    "Username": "Användarnamn",
    "Password": "Lösenord",
    "Confirm password": "Bekräfta lösenord",
    "Administrator (sudo group)": "Administratör (sudo-gruppen)",
    "No interactive accounts found.": "Inga interaktiva konton hittades.",
    "Administrator": "Administratör",
    "Standard": "Standard",
    "The passwords do not match.": "Lösenorden stämmer inte överens.",
    "Enroll two distinct FIDO credentials per account and require them as a second factor.": "Registrera två separata FIDO-autentiseringsuppgifter per konto och kräv dem som en andra faktor.",
    "Connected keys": "Anslutna nycklar",
    "Serial-number discovery does not request administrator authentication. Touch the selected key during enrollment.": "Avläsning av serienummer kräver inte administratörsautentisering. Vidrör den valda nyckeln under registreringen.",
    "Primary": "Primär",
    "Secondary": "Sekundär",
    "Refresh connected keys": "Uppdatera anslutna nycklar",
    "Enroll for account and slot": "Registrera för konto och plats",
    "Enrolled keys": "Registrerade nycklar",
    "Password + YubiKey requirement": "Krav på lösenord + YubiKey",
    "Enabling is refused until every affected account has a key. The setting is added only to each selected PAM service.": "Aktivering nekas tills varje berört konto har en nyckel. Inställningen läggs endast till i varje vald PAM-tjänst.",
    "Graphical and console login": "Grafisk inloggning och konsolinloggning",
    "sudo and sudo -i": "sudo och sudo -i",
    "Save requirements": "Spara krav",
    "administrator": "administratör",
    "standard": "standard",
    "No YubiKey detected, or ykman is unavailable.": "Ingen YubiKey hittades eller så är ykman inte tillgängligt.",
    "Not enrolled": "Inte registrerad",
    "{slot} for {username}": "{slot} för {username}",
    "Enrolled": "Registrerad",
    "Enroll": "Registrera",
    "No keys enrolled.": "Inga nycklar är registrerade.",
    "Un-enroll": "Avregistrera",
    "Choose an account and slot.": "Välj ett konto och en plats.",
    "Touch the YubiKey when it flashes.": "Vidrör YubiKey-enheten när den blinkar.",
    "FIDO2 PIN (if set)": "FIDO2-PIN (om inställd)",
    "The PIN is used only during enrollment and is never stored.": "PIN-koden används endast under registreringen och sparas aldrig.",
    "The FIDO2 PIN is invalid.": "FIDO2-PIN-koden är ogiltig.",
    "This YubiKey requires its FIDO2 PIN. Enter the PIN and try again.": "Den här YubiKey-enheten kräver sin FIDO2-PIN. Ange PIN-koden och försök igen.",
    "The FIDO2 PIN was rejected. Check the PIN and try again.": "FIDO2-PIN-koden nekades. Kontrollera PIN-koden och försök igen.",
    "This YubiKey's FIDO2 PIN is blocked. Reset the FIDO application before enrolling it.": "YubiKey-enhetens FIDO2-PIN är blockerad. Återställ FIDO-programmet innan du registrerar den.",
    "Enrollment failed. Check the FIDO2 PIN, reconnect the YubiKey, and try again.": "Registreringen misslyckades. Kontrollera FIDO2-PIN-koden, anslut YubiKey-enheten på nytt och försök igen.",
    "OS and SSH hardening": "OS- och SSH-härdning",
    "Audit or apply devsec.hardening for Ubuntu 26.04. Imported values override role defaults in both runs.": "Granska eller tillämpa devsec.hardening för Ubuntu 26.04. Importerade värden åsidosätter rollernas standardvärden i båda körningarna.",
    "Pinned collection": "Låst samling",
    "DevSec Hardening {version} is bundled with the package and reused without a runtime download.": "DevSec Hardening {version} ingår i paketet och återanvänds utan nedladdning vid körning.",
    "Custom settings": "Anpassade inställningar",
    "Import a YAML mapping of DevSec role variables. The file is validated and copied into your private configuration directory without sudo.": "Importera en YAML-mappning med DevSec-rollvariabler. Filen valideras och kopieras till din privata konfigurationskatalog utan sudo.",
    "No custom settings imported": "Inga anpassade inställningar har importerats",
    "Import custom-settings.yml": "Importera custom-settings.yml",
    "Current audit status": "Aktuell granskningsstatus",
    "Audit uses Ansible check mode. Apply makes local changes and can change SSH access.": "Granskningen använder Ansibles kontrolläge. Tillämpning gör lokala ändringar och kan påverka SSH-åtkomst.",
    "Run audit": "Kör granskning",
    "Apply hardening": "Tillämpa härdning",
    "Not audited": "Inte granskad",
    "Task results": "Aktivitetsresultat",
    "Select a column heading to sort. Select it again to reverse the order.": "Välj en kolumnrubrik för att sortera. Välj den igen för att vända ordningen.",
    "Task": "Aktivitet",
    "Role": "Roll",
    "Status": "Status",
    "Changed": "Ändrad",
    "playbook": "playbook",
    "Success": "Lyckades",
    "Skipped": "Överhoppad",
    "Failed": "Misslyckades",
    "{count} top-level override loaded": "{count} åsidosättning på toppnivå har lästs in",
    "{count} top-level overrides loaded": "{count} åsidosättningar på toppnivå har lästs in",
    "Import": "Importera",
    "Cancel": "Avbryt",
    "YAML settings": "YAML-inställningar",
    "Choose a local YAML file.": "Välj en lokal YAML-fil.",
    "Imported custom settings. They will override role defaults.": "Anpassade inställningar importerades. De åsidosätter rollernas standardvärden.",
    "Auditing…": "Granskar…",
    "Applying hardening…": "Tillämpar härdning…",
    "Running": "Kör",
    "Apply OS and SSH hardening?": "Tillämpa OS- och SSH-härdning?",
    "This changes the local machine. DevSec SSH defaults can disable password login, root login, and forwarding. Review the audit and ensure you retain a working access path.": "Detta ändrar den lokala datorn. DevSecs SSH-standardvärden kan inaktivera lösenordsinloggning, root-inloggning och vidarebefordran. Granska resultatet och säkerställ att du behåller en fungerande åtkomstväg.",
    "Processed {count} tasks": "Bearbetade {count} aktiviteter",
    "Working": "Arbetar",
    "Complete": "Klar",
    "{success} success · {skipped} skipped · {failed} failed": "{success} lyckades · {skipped} överhoppade · {failed} misslyckades",
    " · {count} need changes": " · {count} behöver ändras",
    "Operation completed.": "Åtgärden slutfördes.",
    "Administrator authentication was cancelled.": "Administratörsautentiseringen avbröts.",
    "The privileged operation failed.": "Den privilegierade åtgärden misslyckades.",
    "Connect only the YubiKey being enrolled so its serial and credential cannot be mismatched.": "Anslut endast den YubiKey som registreras så att serienummer och autentiseringsuppgift inte kan kopplas fel.",
    "pamu2fcfg is not installed.": "pamu2fcfg är inte installerat.",
    "Enrollment failed: {error}": "Registreringen misslyckades: {error}",
    "The key did not complete enrollment.": "Nyckeln slutförde inte registreringen.",
    "The connected YubiKey changed during enrollment; no credential was stored.": "Den anslutna YubiKey-enheten ändrades under registreringen; ingen autentiseringsuppgift sparades.",
    "Usernames must start with a lowercase letter or underscore and contain at most 31 lowercase letters, numbers, underscores, or hyphens.": "Användarnamn måste börja med en gemen bokstav eller ett understreck och får innehålla högst 31 gemena bokstäver, siffror, understreck eller bindestreck.",
    "The YubiKey serial number is invalid.": "YubiKey-serienumret är ogiltigt.",
    "The full name is invalid.": "Det fullständiga namnet är ogiltigt.",
    "Use a password of at least 12 characters.": "Använd ett lösenord med minst 12 tecken.",
    "The password is invalid.": "Lösenordet är ogiltigt.",
    "The settings file contains too many values.": "Inställningsfilen innehåller för många värden.",
    "The settings file is nested too deeply.": "Inställningsfilen har för många nivåer.",
    "Settings numbers must be finite.": "Tal i inställningarna måste vara ändliga.",
    "Every settings key must be a non-empty string.": "Varje inställningsnyckel måste vara en textsträng som inte är tom.",
    "Unsupported YAML value: {type}": "YAML-värdet stöds inte: {type}",
    "Jinja expressions are not allowed in imported settings.": "Jinja-uttryck tillåts inte i importerade inställningar.",
    "Choose an existing YAML file.": "Välj en befintlig YAML-fil.",
    "The settings file must be smaller than 1 MiB.": "Inställningsfilen måste vara mindre än 1 MiB.",
    "Could not read YAML: {error}": "Kunde inte läsa YAML: {error}",
    "The top-level YAML value must be a mapping.": "YAML-värdet på toppnivå måste vara en mappning.",
    "The account {username!r} does not exist.": "Kontot {username!r} finns inte.",
    "YubiKey enrollment is limited to interactive user accounts.": "YubiKey-registrering är begränsad till interaktiva användarkonton.",
    "Disable the affected YubiKey requirement before creating an account, then enroll its key before re-enabling it.": "Inaktivera det berörda YubiKey-kravet innan kontot skapas. Registrera sedan nyckeln innan kravet aktiveras igen.",
    "The account {username!r} already exists.": "Kontot {username!r} finns redan.",
    "Created account {username}.": "Kontot {username} skapades.",
    "The generated credential has an invalid format.": "Den genererade autentiseringsuppgiften har ett ogiltigt format.",
    "The generated credential belongs to a different account.": "Den genererade autentiseringsuppgiften tillhör ett annat konto.",
    "The generated credential is incomplete.": "Den genererade autentiseringsuppgiften är ofullständig.",
    "Choose the primary or secondary slot.": "Välj den primära eller sekundära platsen.",
    "YubiKey {serial} is already enrolled.": "YubiKey {serial} är redan registrerad.",
    "{username} already has a {slot} YubiKey.": "{username} har redan en {slot} YubiKey.",
    "Enrolled YubiKey {serial} as {username}'s {slot} key.": "YubiKey {serial} registrerades som {username}s {slot} nyckel.",
    "{username} has no {slot} YubiKey enrollment.": "{username} har ingen YubiKey-registrering på platsen {slot}.",
    "Disable the affected password + YubiKey requirement before removing this account's last key.": "Inaktivera det berörda kravet på lösenord + YubiKey innan kontots sista nyckel tas bort.",
    "Removed {username}'s {slot} YubiKey enrollment.": "Tog bort {username}s YubiKey-registrering på platsen {slot}.",
    "PAM service does not include common-auth; refusing an unsafe edit.": "PAM-tjänsten inkluderar inte common-auth; en osäker ändring nekas.",
    "PAM service {service!r} is unavailable.": "PAM-tjänsten {service!r} är inte tillgänglig.",
    "libpam-u2f is not installed.": "libpam-u2f är inte installerat.",
    "Refusing to enable a lockout-prone PAM policy. Enroll a key for: {users}": "Nekar att aktivera en PAM-policy som kan orsaka utelåsning. Registrera en nyckel för: {users}",
    "No supported Ubuntu login PAM service was found.": "Ingen PAM-tjänst för Ubuntu-inloggning som stöds hittades.",
    "The Ubuntu sudo PAM service was not found.": "Ubuntus PAM-tjänst för sudo hittades inte.",
    "Updated password + YubiKey requirements.": "Kraven på lösenord + YubiKey uppdaterades.",
    "Hardening is restricted to Ubuntu 26.04.": "Härdning är begränsad till Ubuntu 26.04.",
    "Hardening mode must be audit or apply.": "Härdningsläget måste vara granskning eller tillämpning.",
    "Hardening variables must be a mapping.": "Härdningsvariabler måste vara en mappning.",
    "The Multi Settings Ansible playbook is not installed.": "Multi Settings Ansible-playbook är inte installerad.",
    "The pinned DevSec hardening collection is not installed.": "Den låsta DevSec-härdningssamlingen är inte installerad.",
    "ansible-playbook is not installed.": "ansible-playbook är inte installerat.",
    "Audit completed.": "Granskningen slutfördes.",
    "Hardening completed.": "Härdningen slutfördes.",
    "The request is too large.": "Begäran är för stor.",
    "The request is invalid.": "Begäran är ogiltig.",
    "The requested operation is not allowed.": "Den begärda åtgärden är inte tillåten.",
    "System command failed with exit code {code}.": "Systemkommandot misslyckades med slutkod {code}.",
    "System operation failed: {error}": "Systemåtgärden misslyckades: {error}",
    "The Multi Settings state is unreadable: {error}": "Multi Settings tillstånd kunde inte läsas: {error}",
    "The Multi Settings state has an invalid format.": "Multi Settings tillstånd har ett ogiltigt format.",
    "Could not read trusted {role_name} defaults: {error}": "Kunde inte läsa betrodda standardvärden för {role_name}: {error}",
    "The installed {role_name} defaults are invalid.": "De installerade standardvärdena för {role_name} är ogiltiga.",
    "Unsupported hardening variable: {variables}": "Härdningsvariabeln stöds inte: {variables}",
    "Unsupported hardening variables: {variables}": "Härdningsvariablerna stöds inte: {variables}",
    "Could not identify the operating system: {error}": "Kunde inte identifiera operativsystemet: {error}",
    "Could not verify the installed hardening collection: {error}": "Kunde inte verifiera den installerade härdningssamlingen: {error}",
    "Hardening collection {installed_version} is installed; version {required_version} is required.": "Härdningssamling {installed_version} är installerad; version {required_version} krävs.",
    "Ansible reported a failure.": "Ansible rapporterade ett fel.",
}

_language = DEFAULT_LANGUAGE


def language_file() -> Path:
    return user_config_dir() / "language"


def load_language(path: Path | None = None) -> str:
    preference = path or language_file()
    try:
        language = preference.read_text(encoding="utf-8").strip()
    except OSError:
        return DEFAULT_LANGUAGE
    return language if language in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def set_language(language: str, *, persist: bool = False) -> None:
    if language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language: {language}")
    global _language
    _language = language
    if persist:
        _save_language(language)


def get_language() -> str:
    return _language


def translate(message: str) -> str:
    if _language == "sv":
        return _SWEDISH.get(message, message)
    return message


def has_swedish_translation(message: str) -> bool:
    return message in _SWEDISH


def _save_language(language: str) -> None:
    destination = language_file()
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="language.", dir=destination.parent, text=True
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(f"{language}\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


set_language(load_language())

# Conventional short alias used at string call sites.
_ = translate
