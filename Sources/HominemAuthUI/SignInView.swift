import HominemAuth
import SwiftUI

/// Email/OTP sign-in sheet for the Hominem API. Two steps:
///   1. enter email → request a code
///   2. enter the 6-digit code → verify
///
/// In non-prod (`NODE_ENV != production`) the API uses a scripted email
/// provider — read the code from `~/.hominem/scripted-mailbox.jsonl`.
/// In prod a real 6-digit code is emailed via Resend.
@available(iOS 17, macOS 14, *)
public struct SignInView: View {
    @Bindable var controller: AuthController
    @Environment(\.dismiss) private var dismiss

    @State private var email = ""
    @State private var otp = ""
    @State private var step: Step = .email
    @FocusState private var focusedField: Field?

    private enum Step {
        case email
        case otp
    }

    private enum Field {
        case email
        case otp
    }

    public init(controller: AuthController) {
        self.controller = controller
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(step == .email ? "Sign in to Hominem" : "Check your email")
                .font(.title2.bold())
                .accessibilityAddTraits(.isHeader)

            if step == .email {
                Text("We'll email you a one-time code. No password needed.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                Text("Enter the 6-digit code sent to \(email).")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if step == .email {
                TextField("Email address", text: $email)
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                    .autocorrectionDisabled()
                    .textContentType(.emailAddress)
                    .focused($focusedField, equals: .email)
                    .onSubmit { Task { await sendCode() } }
            } else {
                TextField("6-digit code", text: $otp)
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    .keyboardType(.numberPad)
                    #endif
                    .autocorrectionDisabled()
                    .textContentType(.oneTimeCode)
                    .focused($focusedField, equals: .otp)
                    .onSubmit { Task { await verify() } }
                    .accessibilityLabel("Six-digit code")
            }

            if let errorMessage = controller.errorMessage {
                Text(errorMessage)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .accessibilityLabel("Sign-in error: \(errorMessage)")
            }

            HStack {
                if step == .otp {
                    Button("Back") {
                        otp = ""
                        step = .email
                        controller.clearError()
                        focusedField = .email
                    }
                }
                Spacer()
                Button(step == .email ? "Send Code" : "Sign In") {
                    Task {
                        if step == .email {
                            await sendCode()
                        } else {
                            await verify()
                        }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(controller.isBusy || (step == .email ? email.isEmpty : otp.isEmpty))
            }
            #if os(iOS)
            .controlSize(.large)
            #endif
        }
        .padding(24)
        #if os(macOS)
        .frame(width: 380)
        #endif
        .onAppear { focusedField = (step == .email ? .email : .otp) }
    }

    private func sendCode() async {
        if await controller.requestOTP(email: email) {
            step = .otp
            focusedField = .otp
        } else {
            focusedField = .email
        }
    }

    private func verify() async {
        if await controller.verifyOTP(email: email, otp: otp) {
            dismiss()
        } else {
            focusedField = .otp
        }
    }
}
