import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Button, DatePicker, Form, Input, Message, Modal, Table, Tabs } from './arco-compat';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
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

  it('Form submit surfaces first validation error via Message.warning', async () => {
    const onSubmit = vi.fn();
    const warning = vi.spyOn(Message, 'warning');
    render(
      <Form onSubmit={onSubmit}>
        <Form.Item field="name" label="Name" rules={[{ required: true, message: 'Name is required' }]}>
          <Input />
        </Form.Item>
        <Button htmlType="submit">Save</Button>
      </Form>,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(warning).toHaveBeenCalledWith('Name is required'));
    expect(onSubmit).not.toHaveBeenCalled();
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

  it('Modal Escape key calls onCancel', () => {
    const onCancel = vi.fn();
    render(
      <Modal visible title="Details" onCancel={onCancel}>
        Modal body
      </Modal>,
    );

    expect(screen.getByRole('dialog')).toBeTruthy();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('Table renders expand button when expandedRowRender provided', () => {
    render(
      <Table
        rowKey="id"
        columns={[{ title: 'Name', dataIndex: 'name' }]}
        data={[{ id: '1', name: 'Alice' }]}
        expandedRowRender={(record) => <div>Details for {record.name}</div>}
      />,
    );

    const expandBtn = screen.getByRole('button', { name: 'Expand row' });
    expect(expandBtn).toBeTruthy();
    expect(expandBtn.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByText('Details for Alice')).toBeNull();
  });

  it('Table click expand shows expanded content', () => {
    render(
      <Table
        rowKey="id"
        columns={[{ title: 'Name', dataIndex: 'name' }]}
        data={[{ id: '1', name: 'Alice' }]}
        expandedRowRender={(record) => <div>Details for {record.name}</div>}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Expand row' }));
    expect(screen.getByText('Details for Alice')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Collapse row' }).getAttribute('aria-expanded')).toBe('true');
  });

  it('Table click expand again collapses', () => {
    render(
      <Table
        rowKey="id"
        columns={[{ title: 'Name', dataIndex: 'name' }]}
        data={[{ id: '1', name: 'Alice' }]}
        expandedRowRender={(record) => <div>Details for {record.name}</div>}
      />,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Expand row' }));
    expect(screen.getByText('Details for Alice')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Collapse row' }));
    expect(screen.queryByText('Details for Alice')).toBeNull();
    expect(screen.getByRole('button', { name: 'Expand row' }).getAttribute('aria-expanded')).toBe('false');
  });

  it('DatePicker.RangePicker showTime maps values to datetime-local and emits Arco onChange', () => {
    const onChange = vi.fn();
    const RangePicker = DatePicker.RangePicker;
    render(
      <RangePicker
        showTime
        format="YYYY-MM-DD HH:mm"
        value={['2026-08-07 08:30', '2026-08-07 18:45']}
        onChange={onChange}
      />,
    );

    const start = screen.getByLabelText('Start date') as HTMLInputElement;
    const end = screen.getByLabelText('End date') as HTMLInputElement;
    expect(start.type).toBe('datetime-local');
    expect(end.type).toBe('datetime-local');
    expect(start.value).toBe('2026-08-07T08:30');
    expect(end.value).toBe('2026-08-07T18:45');

    fireEvent.change(start, { target: { value: '2026-08-07T09:15' } });
    expect(onChange).toHaveBeenCalledTimes(1);
    const [dateString, date] = onChange.mock.calls[0] as [string[], (Date | null)[]];
    // Dashboard handleCustomRangeChange(dateString, date) + format YYYY-MM-DD HH:mm
    expect(dateString).toEqual(['2026-08-07 09:15', '2026-08-07 18:45']);
    expect(date[0]).toBeInstanceOf(Date);
    expect(date[1]).toBeInstanceOf(Date);
    expect(date[0]?.getFullYear()).toBe(2026);
    expect(date[0]?.getMonth()).toBe(7);
    expect(date[0]?.getDate()).toBe(7);
    expect(date[0]?.getHours()).toBe(9);
    expect(date[0]?.getMinutes()).toBe(15);
  });

  it('DatePicker.RangePicker date-only mode uses type=date', () => {
    const RangePicker = DatePicker.RangePicker;
    render(<RangePicker value={['2026-01-02', '2026-01-03']} />);
    const start = screen.getByLabelText('Start date') as HTMLInputElement;
    expect(start.type).toBe('date');
    expect(start.value).toBe('2026-01-02');
  });
});
