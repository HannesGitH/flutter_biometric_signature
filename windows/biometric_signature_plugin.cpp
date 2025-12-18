#include "biometric_signature_plugin.h"

#include <windows.h>
#include <objbase.h>
#include <ppltasks.h>

// C++/WinRT Windows Hello APIs
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Storage.Streams.h>

#include <flutter/plugin_registrar_windows.h>

#include <memory>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <functional>

// Base64 encoding utility
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

namespace biometric_signature {

namespace {

// Key identifier for Windows Hello credential
const std::wstring kKeyName = L"BiometricSignatureKey";

// Base64 encode bytes
std::string Base64Encode(const std::vector<uint8_t>& data) {
  if (data.empty()) return "";
  DWORD size = 0;
  CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &size);
  std::string result(size, 0);
  CryptBinaryToStringA(data.data(), static_cast<DWORD>(data.size()),
                       CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &size);
  if (!result.empty() && result.back() == '\0') {
    result.pop_back();
  }
  return result;
}

// Hex encode bytes
std::string HexEncode(const std::vector<uint8_t>& data) {
  if (data.empty()) return "";
  std::ostringstream oss;
  for (uint8_t byte : data) {
    oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

// Format public key according to the requested format
std::string FormatPublicKey(const std::vector<uint8_t>& key_bytes, KeyFormat key_format) {
  std::string base64_key = Base64Encode(key_bytes);
  
  switch (key_format) {
    case KeyFormat::kBase64:
    case KeyFormat::kRaw:
      return base64_key;
    case KeyFormat::kPem: {
      std::string pem = "-----BEGIN PUBLIC KEY-----\n";
      for (size_t i = 0; i < base64_key.length(); i += 64) {
        pem += base64_key.substr(i, 64) + "\n";
      }
      pem += "-----END PUBLIC KEY-----";
      return pem;
    }
    case KeyFormat::kHex:
      return HexEncode(key_bytes);
    default:
      return base64_key;
  }
}

// Format signature according to the requested format
std::string FormatSignature(const std::vector<uint8_t>& sig_bytes, SignatureFormat sig_format) {
  switch (sig_format) {
    case SignatureFormat::kBase64:
    case SignatureFormat::kRaw:
      return Base64Encode(sig_bytes);
    case SignatureFormat::kHex:
      return HexEncode(sig_bytes);
    default:
      return Base64Encode(sig_bytes);
  }
}

// Convert IBuffer to vector
std::vector<uint8_t> IBufferToVector(
    const winrt::Windows::Storage::Streams::IBuffer& buffer) {
  auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(buffer);
  std::vector<uint8_t> data(buffer.Length());
  reader.ReadBytes(data);
  return data;
}

// Convert vector to IBuffer
winrt::Windows::Storage::Streams::IBuffer VectorToIBuffer(
    const std::vector<uint8_t>& data) {
  auto writer = winrt::Windows::Storage::Streams::DataWriter();
  writer.WriteBytes(data);
  return writer.DetachBuffer();
}

}  // namespace

// Static window handle to bring window to foreground before Windows Hello dialogs
static HWND g_window_handle = nullptr;

// Helper function to bring the Flutter window to the foreground
static void BringWindowToForeground() {
  if (g_window_handle != nullptr) {
    SetForegroundWindow(g_window_handle);
    SetFocus(g_window_handle);
  }
}

// static
void BiometricSignaturePlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {

  // Get the Flutter window handle for bringing it to foreground before Windows Hello dialogs
  flutter::FlutterView* view = registrar->GetView();
  if (view != nullptr) {
    g_window_handle = view->GetNativeWindow();
  }

  auto plugin = std::make_unique<BiometricSignaturePlugin>();

  // Set up the Pigeon API
  BiometricSignatureApi::SetUp(registrar->messenger(), plugin.get());

  registrar->AddPlugin(std::move(plugin));
}

BiometricSignaturePlugin::BiometricSignaturePlugin() {}

BiometricSignaturePlugin::~BiometricSignaturePlugin() {}

void BiometricSignaturePlugin::BiometricAuthAvailable(
    std::function<void(ErrorOr<BiometricAvailability> reply)> result) {
  
  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      IsSupportedAsync();
  
  async_op.Completed([result](auto const& op, auto status) {
    BiometricAvailability response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      bool is_supported = op.GetResults();
      
      response.set_can_authenticate(is_supported);
      response.set_has_enrolled_biometrics(is_supported);
      
      flutter::EncodableList biometrics;
      if (is_supported) {
        biometrics.push_back(flutter::CustomEncodableValue(BiometricType::kFingerprint));
      }
      response.set_available_biometrics(biometrics);
      
      if (!is_supported) {
        response.set_reason("Windows Hello is not configured on this device");
      }
    } else {
      response.set_can_authenticate(false);
      response.set_has_enrolled_biometrics(false);
      response.set_available_biometrics(flutter::EncodableList());
      response.set_reason("Failed to check Windows Hello availability");
    }
    
    result(response);
  });
}

void BiometricSignaturePlugin::CreateKeys(
    const CreateKeysConfig* config,
    const KeyFormat& key_format,
    const std::string* prompt_message,
    std::function<void(ErrorOr<KeyCreationResult> reply)> result) {

  // Bring Flutter window to foreground so Windows Hello dialog appears properly
  BringWindowToForeground();

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      RequestCreateAsync(kKeyName, 
          winrt::Windows::Security::Credentials::KeyCredentialCreationOption::
              ReplaceExisting);
  
  async_op.Completed([result, key_format](auto const& op, auto status) {
    KeyCreationResult response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto create_result = op.GetResults();
      
      if (create_result.Status() == 
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
        
        auto credential = create_result.Credential();
        auto public_key_buffer = credential.RetrievePublicKey();
        auto public_key_bytes = IBufferToVector(public_key_buffer);
        auto public_key_formatted = FormatPublicKey(public_key_bytes, key_format);

        response.set_public_key(public_key_formatted);
        response.set_public_key_bytes(public_key_bytes);
        response.set_algorithm("RSA");
        response.set_key_size(static_cast<int64_t>(2048));
        response.set_code(BiometricError::kSuccess);
        response.set_is_hybrid_mode(false);
      } else {
        std::string error_msg = "Failed to create key";
        BiometricError error_code = BiometricError::kUnknown;
        
        switch (create_result.Status()) {
          case winrt::Windows::Security::Credentials::KeyCredentialStatus::UserCanceled:
            error_msg = "User canceled the operation";
            error_code = BiometricError::kUserCanceled;
            break;
          case winrt::Windows::Security::Credentials::KeyCredentialStatus::NotFound:
            error_msg = "Windows Hello not found";
            error_code = BiometricError::kNotAvailable;
            break;
          case winrt::Windows::Security::Credentials::KeyCredentialStatus::SecurityDeviceLocked:
            error_msg = "Security device is locked";
            error_code = BiometricError::kLockedOut;
            break;
          default:
            break;
        }
        
        response.set_error(error_msg);
        response.set_code(error_code);
      }
    } else {
      response.set_error("Operation failed or was canceled");
      response.set_code(BiometricError::kUnknown);
    }
    
    result(response);
  });
}

void BiometricSignaturePlugin::CreateSignature(
    const std::string& payload,
    const CreateSignatureConfig* config,
    const SignatureFormat& signature_format,
    const KeyFormat& key_format,
    const std::string* prompt_message,
    std::function<void(ErrorOr<SignatureResult> reply)> result) {

  if (payload.empty()) {
    SignatureResult response;
    response.set_error("Payload is required");
    response.set_code(BiometricError::kInvalidInput);
    result(response);
    return;
  }

  // Bring Flutter window to foreground so Windows Hello dialog appears properly
  BringWindowToForeground();

  std::string payload_copy = payload;

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      OpenAsync(kKeyName);
  
  async_op.Completed([result, payload_copy, key_format, signature_format](auto const& op, auto status) {
    SignatureResult response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto open_result = op.GetResults();
      
      if (open_result.Status() == 
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
        
        auto credential = open_result.Credential();
        std::vector<uint8_t> payload_bytes(payload_copy.begin(), payload_copy.end());
        auto data_buffer = VectorToIBuffer(payload_bytes);
        
        auto sign_op = credential.RequestSignAsync(data_buffer);
        sign_op.Completed([result, credential, key_format, signature_format](auto const& sign_async, auto sign_status) {
          SignatureResult resp;
          
          if (sign_status == winrt::Windows::Foundation::AsyncStatus::Completed) {
            auto sign_result = sign_async.GetResults();
            
            if (sign_result.Status() == 
                winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
              
              auto signature_buffer = sign_result.Result();
              auto signature_bytes = IBufferToVector(signature_buffer);
              auto signature_formatted = FormatSignature(signature_bytes, signature_format);
              
              auto public_key_buffer = credential.RetrievePublicKey();
              auto public_key_bytes = IBufferToVector(public_key_buffer);
              auto public_key_formatted = FormatPublicKey(public_key_bytes, key_format);

              resp.set_signature(signature_formatted);
              resp.set_signature_bytes(signature_bytes);
              resp.set_public_key(public_key_formatted);
              resp.set_algorithm("RSA");
              resp.set_key_size(static_cast<int64_t>(2048));
              resp.set_code(BiometricError::kSuccess);
            } else {
              std::string error_msg = "Signing failed";
              BiometricError error_code = BiometricError::kUnknown;
              
              switch (sign_result.Status()) {
                case winrt::Windows::Security::Credentials::KeyCredentialStatus::UserCanceled:
                  error_msg = "User canceled the operation";
                  error_code = BiometricError::kUserCanceled;
                  break;
                case winrt::Windows::Security::Credentials::KeyCredentialStatus::SecurityDeviceLocked:
                  error_msg = "Security device is locked";
                  error_code = BiometricError::kLockedOut;
                  break;
                default:
                  break;
              }
              
              resp.set_error(error_msg);
              resp.set_code(error_code);
            }
          } else {
            resp.set_error("Signing operation failed");
            resp.set_code(BiometricError::kUnknown);
          }
          
          result(resp);
        });
        return;  // Don't call result here, the nested callback will
      } else {
        response.set_error("Key not found. Please create keys first.");
        response.set_code(BiometricError::kKeyNotFound);
      }
    } else {
      response.set_error("Failed to open key");
      response.set_code(BiometricError::kUnknown);
    }
    
    result(response);
  });
}

void BiometricSignaturePlugin::DeleteKeys(
    std::function<void(ErrorOr<bool> reply)> result) {
  
  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      DeleteAsync(kKeyName);
  
  async_op.Completed([result](auto const& op, auto status) {
    result(true);  // Return true even if key didn't exist
  });
}

void BiometricSignaturePlugin::GetKeyInfo(
    bool check_validity,
    const KeyFormat& key_format,
    std::function<void(ErrorOr<KeyInfo> reply)> result) {

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      OpenAsync(kKeyName);
  
  async_op.Completed([result, key_format, check_validity](auto const& op, auto status) {
    KeyInfo response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto open_result = op.GetResults();
      
      if (open_result.Status() == 
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
        
        auto credential = open_result.Credential();
        auto public_key_buffer = credential.RetrievePublicKey();
        auto public_key_bytes = IBufferToVector(public_key_buffer);
        auto public_key_formatted = FormatPublicKey(public_key_bytes, key_format);

        response.set_exists(true);
        if (check_validity) {
          response.set_is_valid(true);
        }
        response.set_algorithm("RSA");
        response.set_key_size(static_cast<int64_t>(2048));
        response.set_is_hybrid_mode(false);
        response.set_public_key(public_key_formatted);
      } else {
        response.set_exists(false);
      }
    } else {
      response.set_exists(false);
    }
    
    result(response);
  });
}

void BiometricSignaturePlugin::Decrypt(
    const std::string& payload,
    const PayloadFormat& payload_format,
    const DecryptConfig* config,
    const std::string* prompt_message,
    std::function<void(ErrorOr<DecryptResult> reply)> result) {
  
  DecryptResult response;
  response.set_error("Decryption is not supported on Windows. "
      "Windows Hello is designed for authentication and signing only.");
  response.set_code(BiometricError::kNotAvailable);
  result(response);
}

}  // namespace biometric_signature
