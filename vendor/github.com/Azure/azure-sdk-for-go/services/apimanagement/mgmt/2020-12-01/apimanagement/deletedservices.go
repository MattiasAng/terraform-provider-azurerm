package apimanagement

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/validation"
	"github.com/Azure/go-autorest/tracing"
	"net/http"
)

// DeletedServicesClient is the apiManagement Client
type DeletedServicesClient struct {
	BaseClient
}

// NewDeletedServicesClient creates an instance of the DeletedServicesClient client.
func NewDeletedServicesClient(subscriptionID string) DeletedServicesClient {
	return NewDeletedServicesClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewDeletedServicesClientWithBaseURI creates an instance of the DeletedServicesClient client using a custom endpoint.
// Use this when interacting with an Azure cloud that uses a non-standard base URI (sovereign clouds, Azure stack).
func NewDeletedServicesClientWithBaseURI(baseURI string, subscriptionID string) DeletedServicesClient {
	return DeletedServicesClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// GetByName get soft-deleted Api Management Service by name.
// Parameters:
// serviceName - the name of the API Management service.
// location - the location of the deleted API Management service.
func (client DeletedServicesClient) GetByName(ctx context.Context, serviceName string, location string) (result DeletedServiceContract, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/DeletedServicesClient.GetByName")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: serviceName,
			Constraints: []validation.Constraint{{Target: "serviceName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "serviceName", Name: validation.MinLength, Rule: 1, Chain: nil},
				{Target: "serviceName", Name: validation.Pattern, Rule: `^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`, Chain: nil}}}}); err != nil {
		return result, validation.NewError("apimanagement.DeletedServicesClient", "GetByName", err.Error())
	}

	req, err := client.GetByNamePreparer(ctx, serviceName, location)
	if err != nil {
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "GetByName", nil, "Failure preparing request")
		return
	}

	resp, err := client.GetByNameSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "GetByName", resp, "Failure sending request")
		return
	}

	result, err = client.GetByNameResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "GetByName", resp, "Failure responding to request")
		return
	}

	return
}

// GetByNamePreparer prepares the GetByName request.
func (client DeletedServicesClient) GetByNamePreparer(ctx context.Context, serviceName string, location string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"location":       autorest.Encode("path", location),
		"serviceName":    autorest.Encode("path", serviceName),
		"subscriptionId": autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2020-12-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/locations/{location}/deletedservices/{serviceName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// GetByNameSender sends the GetByName request. The method will close the
// http.Response Body if it receives an error.
func (client DeletedServicesClient) GetByNameSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// GetByNameResponder handles the response to the GetByName request. The method always
// closes the http.Response Body.
func (client DeletedServicesClient) GetByNameResponder(resp *http.Response) (result DeletedServiceContract, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// ListBySubscription lists all soft-deleted services available for undelete for the given subscription.
func (client DeletedServicesClient) ListBySubscription(ctx context.Context) (result DeletedServicesCollectionPage, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/DeletedServicesClient.ListBySubscription")
		defer func() {
			sc := -1
			if result.dsc.Response.Response != nil {
				sc = result.dsc.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.fn = client.listBySubscriptionNextResults
	req, err := client.ListBySubscriptionPreparer(ctx)
	if err != nil {
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "ListBySubscription", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListBySubscriptionSender(req)
	if err != nil {
		result.dsc.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "ListBySubscription", resp, "Failure sending request")
		return
	}

	result.dsc, err = client.ListBySubscriptionResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "ListBySubscription", resp, "Failure responding to request")
		return
	}
	if result.dsc.hasNextLink() && result.dsc.IsEmpty() {
		err = result.NextWithContext(ctx)
		return
	}

	return
}

// ListBySubscriptionPreparer prepares the ListBySubscription request.
func (client DeletedServicesClient) ListBySubscriptionPreparer(ctx context.Context) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"subscriptionId": autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2020-12-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/deletedservices", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListBySubscriptionSender sends the ListBySubscription request. The method will close the
// http.Response Body if it receives an error.
func (client DeletedServicesClient) ListBySubscriptionSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// ListBySubscriptionResponder handles the response to the ListBySubscription request. The method always
// closes the http.Response Body.
func (client DeletedServicesClient) ListBySubscriptionResponder(resp *http.Response) (result DeletedServicesCollection, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}

// listBySubscriptionNextResults retrieves the next set of results, if any.
func (client DeletedServicesClient) listBySubscriptionNextResults(ctx context.Context, lastResults DeletedServicesCollection) (result DeletedServicesCollection, err error) {
	req, err := lastResults.deletedServicesCollectionPreparer(ctx)
	if err != nil {
		return result, autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "listBySubscriptionNextResults", nil, "Failure preparing next results request")
	}
	if req == nil {
		return
	}
	resp, err := client.ListBySubscriptionSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		return result, autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "listBySubscriptionNextResults", resp, "Failure sending next results request")
	}
	result, err = client.ListBySubscriptionResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "listBySubscriptionNextResults", resp, "Failure responding to next results request")
	}
	return
}

// ListBySubscriptionComplete enumerates all values, automatically crossing page boundaries as required.
func (client DeletedServicesClient) ListBySubscriptionComplete(ctx context.Context) (result DeletedServicesCollectionIterator, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/DeletedServicesClient.ListBySubscription")
		defer func() {
			sc := -1
			if result.Response().Response.Response != nil {
				sc = result.page.Response().Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	result.page, err = client.ListBySubscription(ctx)
	return
}

// Purge purges Api Management Service (deletes it with no option to undelete).
// Parameters:
// serviceName - the name of the API Management service.
// location - the location of the deleted API Management service.
func (client DeletedServicesClient) Purge(ctx context.Context, serviceName string, location string) (result DeletedServicesPurgeFuture, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/DeletedServicesClient.Purge")
		defer func() {
			sc := -1
			if result.FutureAPI != nil && result.FutureAPI.Response() != nil {
				sc = result.FutureAPI.Response().StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: serviceName,
			Constraints: []validation.Constraint{{Target: "serviceName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "serviceName", Name: validation.MinLength, Rule: 1, Chain: nil},
				{Target: "serviceName", Name: validation.Pattern, Rule: `^[a-zA-Z](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$`, Chain: nil}}}}); err != nil {
		return result, validation.NewError("apimanagement.DeletedServicesClient", "Purge", err.Error())
	}

	req, err := client.PurgePreparer(ctx, serviceName, location)
	if err != nil {
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "Purge", nil, "Failure preparing request")
		return
	}

	result, err = client.PurgeSender(req)
	if err != nil {
		err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesClient", "Purge", nil, "Failure sending request")
		return
	}

	return
}

// PurgePreparer prepares the Purge request.
func (client DeletedServicesClient) PurgePreparer(ctx context.Context, serviceName string, location string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"location":       autorest.Encode("path", location),
		"serviceName":    autorest.Encode("path", serviceName),
		"subscriptionId": autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2020-12-01"
	queryParameters := map[string]interface{}{
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsDelete(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/providers/Microsoft.ApiManagement/locations/{location}/deletedservices/{serviceName}", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// PurgeSender sends the Purge request. The method will close the
// http.Response Body if it receives an error.
func (client DeletedServicesClient) PurgeSender(req *http.Request) (future DeletedServicesPurgeFuture, err error) {
	var resp *http.Response
	resp, err = client.Send(req, azure.DoRetryWithRegistration(client.Client))
	if err != nil {
		return
	}
	var azf azure.Future
	azf, err = azure.NewFutureFromResponse(resp)
	future.FutureAPI = &azf
	future.Result = func(client DeletedServicesClient) (dsc DeletedServiceContract, err error) {
		var done bool
		done, err = future.DoneWithContext(context.Background(), client)
		if err != nil {
			err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesPurgeFuture", "Result", future.Response(), "Polling failure")
			return
		}
		if !done {
			err = azure.NewAsyncOpIncompleteError("apimanagement.DeletedServicesPurgeFuture")
			return
		}
		sender := autorest.DecorateSender(client, autorest.DoRetryForStatusCodes(client.RetryAttempts, client.RetryDuration, autorest.StatusCodesForRetry...))
		dsc.Response.Response, err = future.GetResult(sender)
		if dsc.Response.Response == nil && err == nil {
			err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesPurgeFuture", "Result", nil, "received nil response and error")
		}
		if err == nil && dsc.Response.Response.StatusCode != http.StatusNoContent {
			dsc, err = client.PurgeResponder(dsc.Response.Response)
			if err != nil {
				err = autorest.NewErrorWithError(err, "apimanagement.DeletedServicesPurgeFuture", "Result", dsc.Response.Response, "Failure responding to request")
			}
		}
		return
	}
	return
}

// PurgeResponder handles the response to the Purge request. The method always
// closes the http.Response Body.
func (client DeletedServicesClient) PurgeResponder(resp *http.Response) (result DeletedServiceContract, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK, http.StatusAccepted, http.StatusNoContent),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}
