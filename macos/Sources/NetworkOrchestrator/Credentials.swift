import Foundation

/// What a profile needs typed in before OpenVPN can start.
struct CredentialNeeds: Decodable, Sendable, Equatable {
  let userPass: Bool
  let keyPassphrase: Bool
  var any: Bool { userPass || keyPassphrase }
}

/// Input held only by the sign-in sheet; Engine owns Keychain persistence.
struct OpenVpnSecrets: Sendable, Equatable {
  var username: String = ""
  var password: String = ""
  var passphrase: String = ""

  /// Whether this covers everything `needs` asks for.
  func satisfies(_ needs: CredentialNeeds) -> Bool {
    (!needs.userPass || (!username.isEmpty && !password.isEmpty))
      && (!needs.keyPassphrase || !passphrase.isEmpty)
  }

  /// Flat arguments for the bridge; only what the profile asks for is sent.
  func arguments(for needs: CredentialNeeds) -> [String: String] {
    var args: [String: String] = [:]
    if needs.userPass {
      args["username"] = username
      args["password"] = password
    }
    if needs.keyPassphrase { args["passphrase"] = passphrase }
    return args
  }
}


/// A connect that is waiting for the user to type credentials.
struct CredentialRequest: Identifiable, Equatable {
  let id = UUID()
  let profile: String
  let name: String
  let needs: CredentialNeeds
  /// Saved credentials were tried and the server refused them.
  let rejected: Bool

  static func == (lhs: CredentialRequest, rhs: CredentialRequest) -> Bool { lhs.id == rhs.id }
}

enum CredentialNotice: String, Decodable, Sendable {
  case keychainUnavailable, storedCredentialsInvalid, rememberFailed, forgetFailed

  @MainActor
  var message: String {
    switch self {
    case .keychainUnavailable:
      L10n.text("Cannot read OpenVPN credentials from Keychain. Unlock the login Keychain or enter credentials for this connection.")
    case .storedCredentialsInvalid:
      L10n.text("Remembered OpenVPN credentials are invalid. Enter credentials again or explicitly forget the saved item.")
    case .rememberFailed:
      L10n.text("Connected, but credentials were not remembered. Unlock the login Keychain and choose Remember on the next successful connection.")
    case .forgetFailed:
      L10n.text("Cannot remove remembered OpenVPN credentials. Unlock the login Keychain and explicitly forget them again; rejected saved credentials will not be used for this attempt.")
    }
  }
}

struct CredentialPrompt: Decodable, Sendable {
  let needs: CredentialNeeds
  let rejected: Bool
  let notice: CredentialNotice?
}

struct CredentialOutcome: Decodable, Sendable {
  let remembered: Bool
  let forgotten: Bool
  let notice: CredentialNotice?
}

enum ConnectProfileOutcome: Decodable, Sendable {
  case connected(CredentialOutcome)
  case credentialsRequired(CredentialPrompt)

  private enum CodingKeys: String, CodingKey { case state, credentials, prompt }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    switch try container.decode(String.self, forKey: .state) {
    case "connected":
      self = .connected(try container.decode(CredentialOutcome.self, forKey: .credentials))
    case "credentialsRequired":
      self = .credentialsRequired(try container.decode(CredentialPrompt.self, forKey: .prompt))
    default:
      throw DecodingError.dataCorruptedError(
        forKey: .state, in: container, debugDescription: "Unknown connection outcome")
    }
  }
}
