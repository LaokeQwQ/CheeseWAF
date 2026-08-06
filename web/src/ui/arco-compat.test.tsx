import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Button, Form, Input, Message, Modal, Tabs } from './arco-compat';

afterEach(() => {
  vi.useRealTimers();
});

describe('arco-compat', () => {
  it('Button type="primary" maps to a clickable button', () => {
    let clicked = false;
    render(
      <Button type="primary" onClick={() => { clicked = true; }}>
        Save
      </Button>,
    );

    const button = screen.getByRole('button', { name: 'Save' });
    expect(button).toBeTruthy();
    fireEvent.click(button);
    expect(clicked).toBe(true);
  });

  it('Form initialValues + Input field displays the seeded value', () => {
    render(
      <Form initialValues={{ name: 'cheese-waf' }}>
        <Form.Item field="name" label="Name">
          <Input />
        </Form.Item>
      </Form>,
    );

    const input = screen.getByLabelText('Name') as HTMLInputElement;
    expect(input.value).toBe('cheese-waf');
  });

  it('Tabs uncontrolled switch shows second pane content', () => {
    render(
      <Tabs defaultActiveTab="one">
        <Tabs.TabPane key="one" title="First">
          Pane One Content
        </Tabs.TabPane>
        <Tabs.TabPane key="two" title="Second">
          Pane Two Content
        </Tabs.TabPane>
      </Tabs>,
    );

    expect(screen.getByText('Pane One Content')).toBeTruthy();
    fireEvent.click(screen.getByRole('tab', { name: 'Second' }));
    expect(screen.getByText('Pane Two Content')).toBeTruthy();
  });

  it('Message.success does not throw', () => {
    vi.useFakeTimers();
    expect(() => Message.success('ok')).not.toThrow();
    vi.runOnlyPendingTimers();
  });

  it('Modal visible renders role=dialog', () => {
    render(
      <Modal visible title="Details">
        Modal body
      </Modal>,
    );

    const dialog = screen.getByRole('dialog');
    expect(dialog).toBeTruthy();
    expect(screen.getByText('Modal body')).toBeTruthy();
  });
});
