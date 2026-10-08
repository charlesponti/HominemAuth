import HominemAuth
import SwiftUI

/// A small menu/status control for showing auth state in an app's toolbar.
/// - Shows the signed-in user's email plus a Sign Out action when authenticated.
/// - Shows a Sign In action that presents `SignInView` in a sheet otherwise.
///
/// Works on iOS + macOS with `@Observable` `AuthController`:
/// ```swift
/// AuthStatusControl(controller: auth)
/// ```
@available(iOS 17, macOS 14, *)
public struct AuthStatusControl: View {
    @Bindable var controller: AuthController
    @State private var showingSignIn = false

    public init(controller: AuthController) {
        self.controller = controller
    }

    public var body: some View {
        Group {
            if let user = controller.signedInUser {
                Menu {
                    Text(user.email)
                    Divider()
                    Button("Sign Out", role: .destructive) {
                        Task { await controller.signOut() }
                    }
                } label: {
                    Label(user.name ?? user.email, systemImage: "person.crop.circle.fill")
                }
                #if os(macOS)
                .menuStyle(.borderlessButton)
                .fixedSize()
                #endif
            } else {
                Button {
                    showingSignIn = true
                } label: {
                    Label("Sign In", systemImage: "person.crop.circle.badge.questionmark")
                }
            }
        }
        .disabled(controller.isBusy)
        .sheet(isPresented: $showingSignIn) {
            SignInView(controller: controller)
            #if os(iOS)
            .presentationDetents([.medium])
            #endif
        }
    }
}

@available(iOS 17, macOS 14, *)
#Preview {
    let auth = AuthClient(configuration: .localDevelopment)
    return AuthStatusControl(controller: AuthController(client: auth))
        .padding()
}
