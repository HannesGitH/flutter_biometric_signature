#include "biometric_signature_plugin.h"

#include <windows.h>
#include <objbase.h>
#include <ppltasks.h>

// C++/WinRT Windows Hello APIs
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Storage.Streams.h>

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <memory>
#include <sstream>
#include <string>
#include <vector>

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

// Static channel to keep it alive
static std::unique_ptr<flutter::MethodChannel<flutter::EncodableValue>> g_channel;

// static
void BiometricSignaturePlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  g_channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(), "com.visionflutter.biometric_signature",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<BiometricSignaturePlugin>();

  g_channel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto &call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

BiometricSignaturePlugin::BiometricSignaturePlugin() {}

BiometricSignaturePlugin::~BiometricSignaturePlugin() {}

void BiometricSignaturePlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  
  if (method_call.method_name().compare("biometricAuthAvailable") == 0) {
    HandleBiometricAuthAvailable(std::move(result));
    
  } else if (method_call.method_name().compare("createKeys") == 0) {
    HandleCreateKeys(method_call, std::move(result));
    
  } else if (method_call.method_name().compare("createSignature") == 0) {
    HandleCreateSignature(method_call, std::move(result));
    
  } else if (method_call.method_name().compare("deleteKeys") == 0) {
    HandleDeleteKeys(std::move(result));
    
  } else if (method_call.method_name().compare("getKeyInfo") == 0) {
    HandleGetKeyInfo(std::move(result));
    
  } else if (method_call.method_name().compare("decrypt") == 0) {
    HandleDecrypt(std::move(result));
    
  } else {
    result->NotImplemented();
  }
}

void BiometricSignaturePlugin::HandleBiometricAuthAvailable(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  // Use shared_ptr to allow capture in lambda
  auto result_ptr = std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
      std::move(result));

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      IsSupportedAsync();
  
  async_op.Completed([result_ptr](auto const& op, auto status) {
    flutter::EncodableMap response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      bool is_supported = op.GetResults();
      
      response[flutter::EncodableValue("canAuthenticate")] = 
          flutter::EncodableValue(is_supported);
      response[flutter::EncodableValue("hasEnrolledBiometrics")] = 
          flutter::EncodableValue(is_supported);
      
      flutter::EncodableList biometrics;
      if (is_supported) {
        biometrics.push_back(flutter::EncodableValue(1));
      }
      response[flutter::EncodableValue("availableBiometrics")] = 
          flutter::EncodableValue(biometrics);
      
      if (!is_supported) {
        response[flutter::EncodableValue("reason")] = 
            flutter::EncodableValue("Windows Hello is not configured on this device");
      }
    } else {
      response[flutter::EncodableValue("canAuthenticate")] = 
          flutter::EncodableValue(false);
      response[flutter::EncodableValue("hasEnrolledBiometrics")] = 
          flutter::EncodableValue(false);
      response[flutter::EncodableValue("availableBiometrics")] = 
          flutter::EncodableValue(flutter::EncodableList());
      response[flutter::EncodableValue("reason")] = 
          flutter::EncodableValue("Failed to check Windows Hello availability");
    }
    
    result_ptr->Success(flutter::EncodableValue(response));
  });
}

void BiometricSignaturePlugin::HandleCreateKeys(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  auto result_ptr = std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
      std::move(result));

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      RequestCreateAsync(kKeyName, 
          winrt::Windows::Security::Credentials::KeyCredentialCreationOption::
              ReplaceExisting);
  
  async_op.Completed([result_ptr](auto const& op, auto status) {
    flutter::EncodableMap response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto create_result = op.GetResults();
      
      if (create_result.Status() == 
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
        
        auto credential = create_result.Credential();
        auto public_key_buffer = credential.RetrievePublicKey();
        auto public_key_bytes = IBufferToVector(public_key_buffer);
        auto public_key_base64 = Base64Encode(public_key_bytes);

        response[flutter::EncodableValue("publicKey")] = 
            flutter::EncodableValue(public_key_base64);
        response[flutter::EncodableValue("publicKeyBytes")] = 
            flutter::EncodableValue(public_key_bytes);
        response[flutter::EncodableValue("algorithm")] = 
            flutter::EncodableValue("RSA");
        response[flutter::EncodableValue("keySize")] = 
            flutter::EncodableValue(2048);
        response[flutter::EncodableValue("code")] = 
            flutter::EncodableValue(0);
        response[flutter::EncodableValue("isHybridMode")] = 
            flutter::EncodableValue(false);
      } else {
        std::string error_msg = "Failed to create key";
        int error_code = 8;
        
        switch (create_result.Status()) {
          case winrt::Windows::Security::Credentials::KeyCredentialStatus::UserCanceled:
            error_msg = "User canceled the operation";
            error_code = 1;
            break;
          case winrt::Windows::Security::Credentials::KeyCredentialStatus::NotFound:
            error_msg = "Windows Hello not found";
            error_code = 2;
            break;
          case winrt::Windows::Security::Credentials::KeyCredentialStatus::SecurityDeviceLocked:
            error_msg = "Security device is locked";
            error_code = 4;
            break;
          default:
            break;
        }
        
        response[flutter::EncodableValue("error")] = 
            flutter::EncodableValue(error_msg);
        response[flutter::EncodableValue("code")] = 
            flutter::EncodableValue(error_code);
      }
    } else {
      response[flutter::EncodableValue("error")] = 
          flutter::EncodableValue("Operation failed or was canceled");
      response[flutter::EncodableValue("code")] = 
          flutter::EncodableValue(8);
    }
    
    result_ptr->Success(flutter::EncodableValue(response));
  });
}

void BiometricSignaturePlugin::HandleCreateSignature(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  std::string payload;
  const auto* args = std::get_if<flutter::EncodableMap>(method_call.arguments());
  if (args) {
    auto it = args->find(flutter::EncodableValue("payload"));
    if (it != args->end()) {
      const auto* payload_val = std::get_if<std::string>(&it->second);
      if (payload_val) {
        payload = *payload_val;
      }
    }
  }

  if (payload.empty()) {
    flutter::EncodableMap response;
    response[flutter::EncodableValue("error")] = 
        flutter::EncodableValue("Payload is required");
    response[flutter::EncodableValue("code")] = 
        flutter::EncodableValue(9);
    result->Success(flutter::EncodableValue(response));
    return;
  }

  auto result_ptr = std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
      std::move(result));
  auto payload_copy = payload;  // Copy for capture

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      OpenAsync(kKeyName);
  
  async_op.Completed([result_ptr, payload_copy](auto const& op, auto status) {
    flutter::EncodableMap response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto open_result = op.GetResults();
      
      if (open_result.Status() == 
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
        
        auto credential = open_result.Credential();
        std::vector<uint8_t> payload_bytes(payload_copy.begin(), payload_copy.end());
        auto data_buffer = VectorToIBuffer(payload_bytes);
        
        auto sign_op = credential.RequestSignAsync(data_buffer);
        sign_op.Completed([result_ptr, credential](auto const& sign_async, auto sign_status) {
          flutter::EncodableMap resp;
          
          if (sign_status == winrt::Windows::Foundation::AsyncStatus::Completed) {
            auto sign_result = sign_async.GetResults();
            
            if (sign_result.Status() == 
                winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
              
              auto signature_buffer = sign_result.Result();
              auto signature_bytes = IBufferToVector(signature_buffer);
              auto signature_base64 = Base64Encode(signature_bytes);
              
              auto public_key_buffer = credential.RetrievePublicKey();
              auto public_key_bytes = IBufferToVector(public_key_buffer);
              auto public_key_base64 = Base64Encode(public_key_bytes);

              resp[flutter::EncodableValue("signature")] = 
                  flutter::EncodableValue(signature_base64);
              resp[flutter::EncodableValue("signatureBytes")] = 
                  flutter::EncodableValue(signature_bytes);
              resp[flutter::EncodableValue("publicKey")] = 
                  flutter::EncodableValue(public_key_base64);
              resp[flutter::EncodableValue("algorithm")] = 
                  flutter::EncodableValue("RSA");
              resp[flutter::EncodableValue("keySize")] = 
                  flutter::EncodableValue(2048);
              resp[flutter::EncodableValue("code")] = 
                  flutter::EncodableValue(0);
            } else {
              std::string error_msg = "Signing failed";
              int error_code = 8;
              
              switch (sign_result.Status()) {
                case winrt::Windows::Security::Credentials::KeyCredentialStatus::UserCanceled:
                  error_msg = "User canceled the operation";
                  error_code = 1;
                  break;
                case winrt::Windows::Security::Credentials::KeyCredentialStatus::SecurityDeviceLocked:
                  error_msg = "Security device is locked";
                  error_code = 4;
                  break;
                default:
                  break;
              }
              
              resp[flutter::EncodableValue("error")] = 
                  flutter::EncodableValue(error_msg);
              resp[flutter::EncodableValue("code")] = 
                  flutter::EncodableValue(error_code);
            }
          } else {
            resp[flutter::EncodableValue("error")] = 
                flutter::EncodableValue("Signing operation failed");
            resp[flutter::EncodableValue("code")] = 
                flutter::EncodableValue(8);
          }
          
          result_ptr->Success(flutter::EncodableValue(resp));
        });
        return;  // Don't call result->Success here, the nested callback will
      } else {
        response[flutter::EncodableValue("error")] = 
            flutter::EncodableValue("Key not found. Please create keys first.");
        response[flutter::EncodableValue("code")] = 
            flutter::EncodableValue(6);
      }
    } else {
      response[flutter::EncodableValue("error")] = 
          flutter::EncodableValue("Failed to open key");
      response[flutter::EncodableValue("code")] = 
          flutter::EncodableValue(8);
    }
    
    result_ptr->Success(flutter::EncodableValue(response));
  });
}

void BiometricSignaturePlugin::HandleDeleteKeys(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  auto result_ptr = std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
      std::move(result));

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      DeleteAsync(kKeyName);
  
  async_op.Completed([result_ptr](auto const& op, auto status) {
    result_ptr->Success(flutter::EncodableValue(true));
  });
}

void BiometricSignaturePlugin::HandleGetKeyInfo(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  auto result_ptr = std::shared_ptr<flutter::MethodResult<flutter::EncodableValue>>(
      std::move(result));

  auto async_op = winrt::Windows::Security::Credentials::KeyCredentialManager::
      OpenAsync(kKeyName);
  
  async_op.Completed([result_ptr](auto const& op, auto status) {
    flutter::EncodableMap response;
    
    if (status == winrt::Windows::Foundation::AsyncStatus::Completed) {
      auto open_result = op.GetResults();
      
      if (open_result.Status() == 
          winrt::Windows::Security::Credentials::KeyCredentialStatus::Success) {
        
        auto credential = open_result.Credential();
        auto public_key_buffer = credential.RetrievePublicKey();
        auto public_key_bytes = IBufferToVector(public_key_buffer);
        auto public_key_base64 = Base64Encode(public_key_bytes);

        response[flutter::EncodableValue("exists")] = 
            flutter::EncodableValue(true);
        response[flutter::EncodableValue("isValid")] = 
            flutter::EncodableValue(true);
        response[flutter::EncodableValue("algorithm")] = 
            flutter::EncodableValue("RSA");
        response[flutter::EncodableValue("keySize")] = 
            flutter::EncodableValue(2048);
        response[flutter::EncodableValue("isHybridMode")] = 
            flutter::EncodableValue(false);
        response[flutter::EncodableValue("publicKey")] = 
            flutter::EncodableValue(public_key_base64);
      } else {
        response[flutter::EncodableValue("exists")] = 
            flutter::EncodableValue(false);
      }
    } else {
      response[flutter::EncodableValue("exists")] = 
          flutter::EncodableValue(false);
    }
    
    result_ptr->Success(flutter::EncodableValue(response));
  });
}

void BiometricSignaturePlugin::HandleDecrypt(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  flutter::EncodableMap response;
  response[flutter::EncodableValue("error")] = 
      flutter::EncodableValue("Decryption is not supported on Windows. "
          "Windows Hello is designed for authentication and signing only.");
  response[flutter::EncodableValue("code")] = 
      flutter::EncodableValue(2);
  result->Success(flutter::EncodableValue(response));
}

}  // namespace biometric_signature
